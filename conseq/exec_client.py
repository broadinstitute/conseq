import collections
from dataclasses import dataclass
import datetime
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from subprocess import Popen
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, Sequence

from conseq import debug_log
from conseq import dep
from conseq import helper
from conseq.dep import Jobs, Obj
from conseq.helper import Remote
from conseq.xref import Resolver
from .types import PropsType
import tempfile
import signal
from conseq.template import MissingTemplateVar, render_template
from conseq.config import get_staging_url


class TemplatePartial:
    def __init__(self, jinja2_env, config, text: str) -> None:
        self.text = text
        # assert isinstance(config, dict)
        self.config = config
        self.jinja2_env = jinja2_env

    def apply(self, **kwargs):
        return render_template(self.jinja2_env, self.text, self.config, **kwargs)


CACHE_KEY_FILENAME = "conseq-cache-key.json"

log = logging.getLogger(__name__)


class PidProcStub:
    def __init__(self, pid: int) -> None:
        self.pid = pid

    def __repr__(self):
        return "<PidProcStub pid:{}>".format(self.pid)

    def poll(self) -> Optional[int]:
        # this is really just to cope with testing, normally the process was created by a different process
        try:
            os.waitpid(self.pid, os.WNOHANG)
        except OSError:
            pass

        # now do the actual test to see if the process exists
        try:
            os.kill(self.pid, 0)
            return None
        except OSError:
            return 0

    def terminate(self):
        os.kill(self.pid, signal.SIGTERM)


def is_valid_value(v):
    if isinstance(v, dict):
        return len(v) == 1 and (
            ("$filename" in v) or ("$value" in v) or ("$file_url" in v)
        )
    return isinstance(v, str)


def _get_tail_file(filename, line_count=20):
    if not os.path.exists(filename):
        log.error("Cannot tail {} because no such file exists".format(filename))
        return

    lines = []
    with open(filename, "rt") as fd:
        fd.seek(0, 2)
        file_len = fd.tell()
        # read at most, the last 100k of the file
        fd.seek(max(0, file_len - 100000), 0)
        lines = fd.read().split("\n")
        for line in lines[-line_count:]:
            lines.append(line + "\n")

    return "".join(lines)


def log_job_output(
    log_path, log_name=None, line_count=20,
):
    if log_name is None:
        log_name = log_path

    if log_path is not None:
        log.error(
            "%s",
            f"Dumping last {line_count} lines of {log_name} ({log_path}):\n{_get_tail_file(log_path)}",
        )


class ExecutionStub:
    pass


class FailedExecutionStub(ExecutionStub):
    def __init__(self, id, message, transform, job_dir=None):
        self.id = id
        self.message = message
        self.transform = transform
        self.job_dir = job_dir

    def get_external_id(self):
        return "FailedExecutionStub:{}".format(self.id)

    def get_completion(self):
        log.error(self.message)
        return ExecResult(self.message, None)

    @property
    def proc(self):
        raise Exception("This stub doesn't have a real process")


class SuccessfulExecutionStub(ExecutionStub):
    def __init__(self, id, outputs, transform=None, job_dir=None):
        self.id = id
        self.outputs = outputs
        self.transform = transform
        self.job_dir = job_dir

    @property
    def proc(self):
        raise Exception("This stub doesn't have a real process")

    def get_external_id(self):
        return "SuccessfulExecutionStub:{}".format(self.id)

    def get_completion(self):
        return ExecResult(None, self.outputs)


def grep_logs(log_grep_state: Dict[str, int], output_files: List[str], pattern):
    # make a copy of the state, where state is a map of filename -> last read offset
    next_log_grep_state = dict(log_grep_state)

    filtered_lines = []
    for output_file in output_files:
        if not os.path.exists(output_file):
            continue

        # read file from where we left off
        offset = next_log_grep_state.get(output_file, 0)
        with open(output_file, "rb") as fd:
            fd.seek(offset)
            buffer = fd.read()
            new_offset = fd.tell()
        next_log_grep_state[output_file] = new_offset
        lines = buffer.decode("utf8").split("\n")

        # drop all lines except those that match pattern
        filtered_lines.extend(
            [line for line in lines if pattern.match(line) is not None]
        )

    return next_log_grep_state, filtered_lines


@dataclass
class ExecResult:
    failure_msg: Optional[str]
    outputs: Optional[List[Dict[str, Any]]]
    cache_key: Optional[str] = None


class ClientExecution:
    exec_xref: str

    def __init__(
        self,
        transform: str,
        id: int,
        job_dir: str,
        proc: Union[PidProcStub, Popen],
        outputs: Optional[List[PropsType]],
        captured_stdouts: Union[List[str], Tuple[str, str]],
        desc_name: str,
        executor_parameters: dict,
        *,
        watch_regex=None,
    ) -> None:
        self.transform = transform
        self.id = id
        self.proc = proc
        self.job_dir = job_dir
        self.outputs = outputs
        self.captured_stdouts = captured_stdouts
        self.desc_name = desc_name
        self.log_grep_state = {}
        self.watch_regex = watch_regex
        self.executor_parameters = executor_parameters
        assert job_dir != None

    def _resolve_filenames(self, props):
        props_copy = {}
        for k, v in props.items():
            if isinstance(v, dict) and "$filename" in v:
                full_filename = os.path.join(self.job_dir, v["$filename"])
                if not os.path.exists(full_filename):
                    raise Exception(
                        "Attempted to publish results which referenced file that did not exist: {}".format(
                            full_filename
                        )
                    )
                v = {"$filename": full_filename}
            props_copy[k] = v
        return props_copy

    def get_state_label(self) -> str:
        return "local-run"

    def get_external_id(self) -> str:
        d = dict(
            transform=self.transform,
            id=self.id,
            job_dir=self.job_dir,
            pid=self.proc.pid,
            outputs=self.outputs,
            captured_stdouts=self.captured_stdouts,
            desc_name=self.desc_name,
            executor_parameters=self.executor_parameters,
        )
        return json.dumps(d)

    def cancel(self):
        log.warning("Killing %s (%s)", self.desc_name, repr(self.proc))
        self.proc.terminate()

    @property
    def results_path(self):
        return os.path.join(self.job_dir, "results.json")

    def _log_failure(self, failure):
        log.error("Task failed %s: %s", self.desc_name, failure)
        _log_local_failure(self.captured_stdouts)

    def get_completion(self) -> ExecResult:
        result = self._get_completion()
        if result.failure_msg is not None:
            self._log_failure(result.failure_msg)
        return result

    def _get_completion(self) -> ExecResult:
        # breakpoint()
        if self.watch_regex is not None:
            self.log_grep_state, log_output = grep_logs(
                self.log_grep_state, self.captured_stdouts, self.watch_regex
            )

            for line in log_output:
                print("{} output: {}".format(self.job_dir, line))

        retcode = self.proc.poll()

        if retcode == None:
            return ExecResult(None, None)

        if retcode != 0:
            return ExecResult("shell command failed with {}".format(retcode), None)

        retcode_file = os.path.join(self.job_dir, "retcode.txt")
        try:
            with open(retcode_file) as fd:
                retcode = int(fd.read())
                if retcode != 0:
                    return ExecResult("failed with {}".format(retcode), None)
        except FileNotFoundError:
            return ExecResult("No retcode file {}".format(retcode_file), None)

        if self.outputs != None:
            results = {"outputs": self.outputs}
        else:
            if not os.path.exists(self.results_path):
                return ExecResult(
                    "rule {} completed successfully, but no results.json file written to working directory".format(
                        self.transform
                    ),
                    None,
                )

            with open(self.results_path) as fd:
                results = json.load(fd)
                # quick verify that results is well formed
                error = None
                if not isinstance(results, dict):
                    error = "results.json did not contain a valid object"
                else:
                    artifacts = results.get("outputs", None)
                    if not isinstance(artifacts, list):
                        error = "No outputs listed in artifacts"
                    else:
                        for artifact in artifacts:
                            if not isinstance(artifact, dict):
                                error = "artifacts must all be objects"
                                break
                            else:
                                for k, v in artifact.items():
                                    if not (isinstance(k, str) and is_valid_value(v)):
                                        error = (
                                            "artifact's key/values must both be strings"
                                        )
                                        break
                                if error is not None:
                                    break
                if error:
                    return ExecResult(error, None)

        # breakpoint()
        cache_key = None
        cache_key_file = os.path.join(self.job_dir, CACHE_KEY_FILENAME)
        if os.path.exists(cache_key_file):
            with open(cache_key_file, "rt") as fd:
                cache_key = fd.read()

        log.info(
            "Rule {} completed ({}). Results: {}".format(
                self.transform, self.job_dir, results
            )
        )
        outputs = [self._resolve_filenames(o) for o in results["outputs"]]

        # print summary of output files with full paths
        files_written = []
        for output in outputs:
            for value in output.values():
                if isinstance(value, dict) and "$filename" in value:
                    files_written.append(value["$filename"])
        if len(files_written):
            log.warning(
                "Rule %s wrote the following files:\n%s",
                self.transform,
                "\n".join(["\t" + x for x in files_written]),
            )

        return ExecResult(None, outputs, cache_key=cache_key)


class DelegateExecution(ClientExecution):
    def __init__(
        self,
        transform: str,
        id: int,
        job_dir: str,
        proc: Union[PidProcStub, Popen],
        outputs: Optional[List[PropsType]],
        captured_stdouts: Union[List[str], Tuple[str, str]],
        desc_name: str,
        remote: Remote,
        file_fetcher: Callable,
        label: str,
        results_path: str,
        executor_parameters: dict,
        delegate_log: str,
    ) -> None:
        super(DelegateExecution, self).__init__(
            transform,
            id,
            job_dir,
            proc,
            outputs,
            captured_stdouts,
            desc_name,
            executor_parameters,
        )
        self.remote = remote
        self.file_fetcher = file_fetcher
        self.label = label
        self._results_path = results_path
        self.delegate_log = delegate_log

    def get_state_label(self) -> str:
        return self.label

    def get_external_id(self) -> str:
        d = dict(
            transform=self.transform,
            id=self.id,
            outputs=self.outputs,
            captured_stdouts=self.captured_stdouts,
            desc_name=self.desc_name,
            remote_url=self.remote.remote_url,
            job_dir=self.job_dir,
            local_job_dir=self.job_dir,
            label=self.label,
            results_path=self._results_path,
            executor_parameters=self.executor_parameters,
            delegate_log=self.delegate_log,
        )
        if hasattr(self.proc, "pid"):
            d["pid"] = self.proc.pid
        else:
            d["x_job_id"] = self.proc.job_id

        return json.dumps(d)

    def _log_failure(self, msg):
        _log_remote_failure(self.file_fetcher, msg)
        _log_local_failure(self.captured_stdouts)

    def _get_completion(self,) -> ExecResult:
        retcode = self.proc.poll()

        if retcode == None:
            return ExecResult(None, None)

        if retcode != 0:
            return ExecResult("shell command failed with {}".format(retcode), None)

        log.debug("About to download retcode.json")

        retcode_content = self.remote.download_as_str("retcode.json")
        if retcode_content is not None:
            retcode = json.loads(retcode_content)["retcode"]
        else:
            log.warning("Attempted to read retcode.json but got None")
            retcode = None

        if retcode != 0:
            return ExecResult(
                "inner shell command failed with {}".format(repr(retcode)), None
            )

        results_str = self.remote.download_as_str(self._results_path)
        if results_str is None:
            return ExecResult(
                "script reported success but results.json is missing!", None
            )

        results = json.loads(results_str)

        if self.remote.exists(CACHE_KEY_FILENAME):
            cache_key = self.remote.download_as_str(CACHE_KEY_FILENAME)
        else:
            cache_key = None

        log.info(
            "Rule {} completed ({}). Results: {}".format(
                self.desc_name, self.job_dir, results
            )
        )
        assert type(results["outputs"]) == list
        outputs = [_resolve_filenames(self.remote, o) for o in results["outputs"]]

        return ExecResult(None, outputs, cache_key=cache_key)


def write_wrapper_script(
    wrapper_path: str,
    job_dir: Optional[str],
    prologue: str,
    run_stmts: List[str],
    retcode_path: Optional[str],
) -> None:
    with open(wrapper_path, "wt") as fd:
        fd.write("set -ex\n")
        if job_dir is not None:
            job_dir = os.path.abspath(job_dir)
            fd.write("cd {job_dir}\n".format(**locals()))

        fd.write(prologue + "\n")

        fd.write("EXIT_STATUS=0\n")
        for run_stmt in run_stmts:
            fd.write("if [ $EXIT_STATUS == 0 ]; then\n")
            # based on http://veithen.github.io/2014/11/16/sigterm-propagation.html to propagate killing of child proc if this proc is killed.
            fd.write("  # Propagate kill if shell receives SIGTERM or SIGINT\n")
            fd.write("  trap 'kill -TERM $PID' TERM INT\n")
            fd.write("  " + run_stmt.strip() + " &\n")
            fd.write("  PID=$!\n")
            fd.write("  wait $PID\n")
            fd.write("  trap - TERM INT\n")
            fd.write("  wait $PID\n")
            fd.write("  EXIT_STATUS=$?\n")
            fd.write("fi\n\n")

        if retcode_path is not None:
            fd.write("echo $EXIT_STATUS > {retcode_path}\n".format(**locals()))


def local_exec_script(
    name: str,
    id: int,
    job_dir: str,
    run_stmts: List[str],
    outputs: List[Any],
    capture_output: bool,
    prologue: str,
    desc_name: str,
    watch_regex,
) -> ClientExecution:
    stdout_path = os.path.join(job_dir, "stdout.txt")
    stderr_path = os.path.join(job_dir, "stderr.txt")
    # results_path = os.path.join(job_dir, "results.json")

    stdout_path = os.path.abspath(stdout_path)
    stderr_path = os.path.abspath(stderr_path)
    retcode_path = os.path.abspath(os.path.join(job_dir, "retcode.txt"))

    wrapper_path = os.path.join(job_dir, "wrapper.sh")
    write_wrapper_script(wrapper_path, job_dir, prologue, run_stmts, retcode_path)

    if capture_output:
        bash_cmd = "exec bash {wrapper_path} > {stdout_path} 2> {stderr_path}".format(
            **locals()
        )
        captured_stdouts = (stdout_path, stderr_path)
        close_fds = True
    else:
        bash_cmd = "exec bash {wrapper_path}".format(**locals())
        captured_stdouts = None
        close_fds = False

    # log.info("Starting task in %s", job_dir)
    log.debug("executing: %s", bash_cmd)

    # create child in new process group so ctrl-c doesn't kill child process
    proc = subprocess.Popen(
        ["bash", "-c", bash_cmd], close_fds=close_fds, preexec_fn=os.setsid
    )

    with open(os.path.join(job_dir, "description.txt"), "w") as fd:
        fd.write(desc_name)

    return ClientExecution(
        name,
        id,
        job_dir,
        proc,
        outputs,
        captured_stdouts,
        desc_name,
        {},
        watch_regex=watch_regex,
    )


def fetch_urls(obj: PropsType, resolver: Resolver) -> Dict[str, str]:
    assert isinstance(obj, dict)
    new_obj = {}
    for k, v in obj.items():
        if isinstance(v, dict) and "$file_url" in v:
            url = v["$file_url"]
            filename = resolver.resolve(url)["filename"]
            new_obj[k] = filename
        else:
            new_obj[k] = v
    return new_obj


def needs_resolution(obj: PropsType) -> bool:
    if not ("$xref_url" in obj):
        return False
    # Just noticed this.  weird, isn't it?  I think this should _probably_ be removed.
    for v in obj.values():
        if isinstance(v, dict) and "$value" in v:
            return False
    return True


def flatten_value(v: Union[Dict[str, str], str]) -> str:
    if isinstance(v, dict) and len(v) == 1 and "$value" in v:
        v = v["$value"]
    elif isinstance(v, dict) and len(v) == 1 and "$filename" in v:
        v = os.path.abspath(v["$filename"])
    return v


def flatten_parameters(d: Dict[str, str]) -> Dict[str, str]:
    "make dictionary into simple (string, string) pairs by handling $value and $filename special cases"
    pairs = []
    for k, v in d.items():
        v = flatten_value(v)
        pairs.append((k, v))
    return dict(pairs)


from .types import InputsType


def preprocess_xref_inputs(j: Jobs, resolver: Resolver, inputs: InputsType) -> bool:
    xrefs_resolved = [False]

    def resolve(obj_):
        assert isinstance(obj_, dep.Obj)
        obj = obj_.props
        obj_copy = None

        if needs_resolution(obj):
            extra_params = resolver.resolve(obj["$xref_url"])
            obj_copy = dict(obj)
            for k, v in extra_params.items():
                obj_copy[k] = {"$value": v}

        if not obj_copy is None:
            timestamp = datetime.datetime.now().isoformat()
            # persist new version of object with extra properties
            j.add_obj(obj_.space, timestamp, obj_copy)
            xrefs_resolved[0] = True

    for bound_name, obj_or_list in inputs:
        if isinstance(obj_or_list, list) or isinstance(obj_or_list, tuple):
            list_ = obj_or_list
        else:
            list_ = [obj_or_list]
        for obj_ in list_:
            resolve(obj_)

    return xrefs_resolved[0]


class ResolveState:
    def add_script(self, script):
        raise Exception("Cannot call on base class")


class NullResolveState(ResolveState):
    def __init__(self, files_to_copy: List[Any]) -> None:
        self.files_to_copy = files_to_copy

    #        print("self.files_to_copy", self.files_to_copy)

    def add_script(self, script):
        pass


class ExternProc:
    def __init__(
        self,
        job_id,
        check_cmd_template,
        is_running_pattern,
        terminate_cmd_template,
        complete_cmd_template,
        executor_parameters,
        delegate_log,
    ):
        self.job_id = job_id
        self.check_cmd_template = check_cmd_template
        self.terminate_cmd_template = terminate_cmd_template
        self.is_running_pattern = is_running_pattern
        self.complete_cmd_template = complete_cmd_template
        self.executor_parameters = executor_parameters
        self.complete_cmd_ran = False
        self.delegate_log = delegate_log

    def poll(self):
        check_cmd = self.check_cmd_template.apply(
            JOB_ID=self.job_id, parameters=self.executor_parameters
        ).strip()
        output = subprocess.check_output(check_cmd, shell=True)
        output = output.decode("utf8")
        m = re.search(self.is_running_pattern, output)
        if m is None:
            # the job is done running if we can't find the pattern
            if not self.complete_cmd_ran and self.complete_cmd_template is not None:
                complete_cmd = self.complete_cmd_template.apply(
                    JOB_ID=self.job_id, parameters=self.executor_parameters
                ).strip()
                log.warning(
                    "Executing: %s and writing output to %s",
                    complete_cmd,
                    self.delegate_log,
                )
                with open(self.delegate_log, "at") as log_fd:
                    subprocess.call(
                        complete_cmd,
                        shell=True,
                        stdout=log_fd,
                        stderr=subprocess.STDOUT,
                    )
                self.complete_cmd_ran = True

            return 0
        return None

    def terminate(self):
        terminate_cmd = self.check_cmd_template.apply(
            JOB_ID=self.job_id, parameters=self.executor_parameters
        ).strip()
        log.warning("Executing: %s", terminate_cmd)
        subprocess.check_call(terminate_cmd, shell=True)


# class ReportSuccessProcStub:
#     def __init__(self):
#         self.pid = 10000000
#
#     def poll(self):
#         return 0

from collections import namedtuple
from typing import Optional
from .types import BoundInput


def bind_inputs(rule, inputs: Sequence[Tuple[str, any]]):
    by_name = {input.variable: input for input in rule.inputs}
    return [BoundInput(name, value, by_name[name].copy_to) for name, value in inputs]


class ExecClient:
    def reattach(self, external_ref):
        raise NotImplementedError()

    def preprocess_inputs(
        self, resolver: Resolver, inputs: Tuple[BoundInput]
    ) -> Tuple[Dict[str, Dict[str, str]], NullResolveState]:
        raise NotImplementedError()

    def exec_script(
        self,
        name: str,
        id: int,
        job_dir: str,
        run_stmts: List[str],
        outputs: Optional[List[Any]],
        capture_output: bool,
        prologue: str,
        desc_name: str,
        resolve_state: NullResolveState,
        resources: Dict[str, float],
        watch_regex,
    ) -> ClientExecution:
        raise NotImplementedError()


class LocalExecClient(ExecClient):
    def __init__(self, resources: Dict[Any, Any]) -> None:
        self.resources = resources

    def reattach(self, external_ref):
        d = json.loads(external_ref)
        return ClientExecution(
            d["transform"],
            d["id"],
            d["job_dir"],
            PidProcStub(d["pid"]),
            d["outputs"],
            d["captured_stdouts"],
            d["desc_name"],
            {},
        )

    def preprocess_inputs(
        self, resolver: Resolver, inputs: Sequence[BoundInput]
    ) -> Tuple[Dict[str, Dict[str, str]], NullResolveState]:
        files_to_copy = []

        def resolve(obj_: dep.Obj, copy_to: Optional[str]):
            assert isinstance(obj_, dep.Obj)

            obj = obj_.props
            assert isinstance(obj, dict)

            obj = fetch_urls(obj, resolver)
            obj = flatten_parameters(obj)
            if obj.get("type") == "$fileref":
                filename = obj.get("filename")
                destination = obj.get("destination")
                if copy_to is not None:
                    files_to_copy.append((filename, copy_to))
                    obj = dict(obj)
                    obj["filename"] = copy_to
                elif destination:
                    files_to_copy.append((filename, destination))
                    obj["filename"] = destination
            else:
                assert not copy_to
            return obj

        result = {}
        for input in inputs:
            obj_or_list = input.value
            copy_to = input.copy_to
            bound_name = input.name

            if isinstance(obj_or_list, list) or isinstance(obj_or_list, tuple):
                list_ = obj_or_list
                result[bound_name] = [resolve(obj_, copy_to) for obj_ in list_]
            else:
                obj_ = obj_or_list
                result[bound_name] = resolve(obj_, copy_to)

        return result, NullResolveState(files_to_copy)

    def exec_script(
        self,
        name: str,
        id: int,
        job_dir: str,
        run_stmts: List[str],
        outputs: Optional[List[Any]],
        capture_output: bool,
        prologue: str,
        desc_name: str,
        resolve_state: ResolveState,
        resources: Dict[str, float],
        watch_regex,
        executor_parameters: Dict[str, str],
    ) -> ClientExecution:
        assert isinstance(resolve_state, NullResolveState)

        for src, dst in resolve_state.files_to_copy:
            # print("copying ", src, os.path.join(job_dir, dst))
            shutil.copy(src, os.path.join(job_dir, dst))

        return local_exec_script(
            name,
            id,
            job_dir,
            run_stmts,
            outputs,
            capture_output,
            prologue,
            desc_name,
            watch_regex,
        )


def drop_prefix(prefix, value):
    assert value[: len(prefix)] == prefix, "prefix=%r, value=%r" % (prefix, value)
    return value[len(prefix) :]


def push_to_cas_with_pullmap(
    remote: Remote, source_and_dest: List[Tuple[str, str]], url_and_dest: List[Any]
) -> str:
    source_and_dest = [
        (os.path.abspath(source), dest) for source, dest in source_and_dest
    ]
    log.debug("push_to_cas_with_pullmap, filenames: %s", source_and_dest)
    name_mapping = helper.push_to_cas(
        remote, [source for source, dest in source_and_dest]
    )

    mapping = [
        dict(remote="{}/{}".format(remote.remote_url, name_mapping[source]), local=dest)
        for source, dest in source_and_dest
    ]

    mapping += [dict(remote=src_url, local=dest) for src_url, dest in url_and_dest]

    log.debug("name_mapping: %s", name_mapping)
    log.debug("mapping: %s", mapping)
    for rec in mapping:
        if rec["local"].startswith("/"):
            rec["local"] = os.path.relpath(rec["local"], remote.local_dir)

    debug_log.log_pullmap(mapping)

    mapping_str = json.dumps(dict(mapping=mapping), sort_keys=True)
    log.debug("Mapping str: %s", mapping_str)
    fd = tempfile.NamedTemporaryFile(mode="wt")
    fd.write(mapping_str)
    fd.flush()
    map_name = list(helper.push_to_cas(remote, [fd.name]).values())[0]
    fd.close()

    return "{}/{}".format(remote.remote_url, map_name)


def process_inputs_for_publishing(cas_remote, inputs: Tuple[BoundInput]):
    def resolve(obj_):
        assert isinstance(obj_, dep.Obj)
        obj = obj_.props
        assert isinstance(obj, dict)

        new_obj = {}
        for k, v in obj.items():
            if type(v) == dict and "$filename" in v:
                cur_name = v["$filename"]
                new_url = (
                    cas_remote.remote_url
                    + "/"
                    + helper.push_to_cas(cas_remote, [cur_name])[cur_name]
                )
                v = new_url
            elif isinstance(v, dict) and "$file_url" in v:
                v = v["$file_url"]
            elif isinstance(v, dict) and len(v) == 1 and "$value" in v:
                v = v["$value"]
            else:
                assert isinstance(
                    v, str
                ), "Expected value for {} ({}) to be a string but was {}".format(
                    k, repr(v), type(v)
                )

            new_obj[k] = v

        return new_obj

    result = {}
    for input in inputs:
        bound_name, obj_or_list = (input.name, input.value)
        if isinstance(obj_or_list, list) or isinstance(obj_or_list, tuple):
            list_ = obj_or_list
            result[bound_name] = [resolve(obj_) for obj_ in list_]
        else:
            obj_ = obj_or_list
            result[bound_name] = resolve(obj_)
    log.debug("preprocess_inputs, after inputs: %s", result)

    return result


def process_inputs_for_remote_exec(
    inputs: Tuple[BoundInput],
) -> Tuple[List[Any], List[Tuple[str, str]], Dict[str, Dict[str, str]]]:
    log.debug("preprocess_inputs, before inputs: %s", inputs)
    files_to_upload_and_download = []
    files_to_download = []

    def next_file_index():
        return len(files_to_upload_and_download) + len(files_to_download)

    # need to find all files that will be downloaded and update with $filename of what eventual local location will be.
    def resolve(obj_, copy_to):
        assert isinstance(obj_, dep.Obj)
        obj = obj_.props
        assert isinstance(obj, dict)

        # temporarily using dest prop for filerefs. This works because filerefs only have one file
        # probably need to clean this up eventually
        destination = None
        if obj.get("type") == "$fileref":
            destination = flatten_value(obj.get("destination"))
            if copy_to:
                destination = copy_to

        new_obj = {}
        for k, v in obj.items():
            if type(v) == dict and "$filename" in v:
                cur_name = v["$filename"]
                # Need to do something to avoid collisions.  Store under working dir?  maybe temp/filename-v
                if destination is None:
                    new_name = "temp/{}.{}".format(
                        os.path.basename(cur_name), next_file_index()
                    )
                else:
                    new_name = destination
                files_to_upload_and_download.append((cur_name, new_name))
                v = new_name
            elif isinstance(v, dict) and "$file_url" in v:
                cur_name = v["$file_url"]
                if destination is None:
                    new_name = "temp/{}.{}".format(
                        os.path.basename(cur_name), next_file_index()
                    )
                else:
                    new_name = destination
                files_to_download.append((cur_name, new_name))
                v = new_name
            elif isinstance(v, dict) and len(v) == 1 and "$value" in v:
                v = v["$value"]
            else:
                assert isinstance(
                    v, str
                ), "Expected value for {} ({}) to be a string but was {}".format(
                    k, repr(v), type(v)
                )

            new_obj[k] = v

        return new_obj

    result = {}
    for input in inputs:
        bound_name, obj_or_list, copy_to = input.name, input.value, input.copy_to
        if isinstance(obj_or_list, list) or isinstance(obj_or_list, tuple):
            list_ = obj_or_list
            result[bound_name] = [resolve(obj_, copy_to) for obj_ in list_]
        else:
            obj_ = obj_or_list
            result[bound_name] = resolve(obj_, copy_to)
    log.debug("preprocess_inputs, after inputs: %s", result)
    log.debug("files_to_upload_and_download: %s", files_to_upload_and_download)
    log.debug("files_to_download: %s", files_to_download)
    return files_to_download, files_to_upload_and_download, result


def create_publish_exec_client(config):
    return PublishExecClient(get_staging_url(config))


def make_results_path(cas_remote_url: str, pull_map_url: str) -> str:
    import hashlib

    hash = hashlib.sha256(pull_map_url.encode("utf-8")).hexdigest()
    return os.path.join(cas_remote_url, "results", hash)


def load_existing_results(id, remote, results_path, transform):
    log.warning(
        "Job appears to have already been run, taking results from %s", results_path
    )
    results_str = remote.download_as_str(results_path)
    results = json.loads(results_str)
    return SuccessfulExecutionStub(id, outputs=results["outputs"], transform=transform)


class PublishExecClient:
    def __init__(self, cas_remote_url):
        self.cas_remote = helper.new_remote(cas_remote_url, ".")

    def preprocess_inputs(self, resolver, inputs):
        result = process_inputs_for_publishing(self.cas_remote, inputs)
        return result, None


class AsyncDelegateExecClient:
    def __init__(
        self,
        resources,
        label,
        local_workdir,
        remote_url,
        cas_remote_url,
        helper_path,
        run_command_template,
        python_path,
        check_cmd_template,
        is_running_pattern,
        terminate_cmd_template,
        complete_cmd_template,
        x_job_id_pattern,
        recycle_past_runs,
    ):
        assert isinstance(run_command_template, TemplatePartial)
        assert isinstance(check_cmd_template, TemplatePartial)
        assert isinstance(terminate_cmd_template, TemplatePartial)
        assert isinstance(helper_path, TemplatePartial)
        assert complete_cmd_template is None or isinstance(
            complete_cmd_template, TemplatePartial
        )
        self.resources = resources
        self.helper_path = helper_path
        self.local_workdir = local_workdir
        self.remote_url = remote_url
        self.run_command_template = run_command_template
        self.cas_remote_url = cas_remote_url
        self.python_path = python_path
        self.label = label
        self.check_cmd_template = check_cmd_template
        self.is_running_pattern = is_running_pattern
        self.terminate_cmd_template = terminate_cmd_template
        self.x_job_id_pattern = x_job_id_pattern
        self.recycle_past_runs = recycle_past_runs
        self.complete_cmd_template = complete_cmd_template

    def _extract_job_id(self, output):
        m = re.search(self.x_job_id_pattern, output)
        if m is None:
            raise Exception(
                "Pattern {} could not be found in {}".format(
                    self.x_job_id_pattern, output
                )
            )
        print("output", output)
        job_id = m.group(1)
        assert job_id is not None

        return job_id

    def reattach(self, external_ref):
        d = json.loads(external_ref)
        remote = helper.new_remote(d["remote_url"], d["local_job_dir"],)
        file_fetcher = self._mk_file_fetcher(remote)
        executor_parameters = d["executor_parameters"]
        proc = ExternProc(
            d["x_job_id"],
            self.check_cmd_template,
            self.is_running_pattern,
            self.terminate_cmd_template,
            self.complete_cmd_template,
            executor_parameters,
            d["delegate_log"],
        )
        return DelegateExecution(
            d["transform"],
            d["id"],
            d["job_dir"],
            proc,
            d["outputs"],
            d["captured_stdouts"],
            d["desc_name"],
            remote,
            file_fetcher,
            d["label"],
            d["results_path"],
            executor_parameters,
            d["delegate_log"],
        )

    def preprocess_inputs(self, resolver, inputs: Tuple[BoundInput]):
        (
            files_to_download,
            files_to_upload_and_download,
            result,
        ) = process_inputs_for_remote_exec(inputs)
        return (
            result,
            RemoteResolveState(files_to_upload_and_download, files_to_download),
        )

    def exec_script(
        self,
        name,
        id,
        job_dir,
        run_stmts,
        outputs,
        capture_output,
        prologue,
        desc_name,
        resolver_state,
        resources,
        watch_regex,
        executor_parameters: Dict[str, str],
    ):
        assert (
            watch_regex is None
        ), "delegated executors cannot watch logs, watch-regex not allowed"
        assert job_dir[: len(self.local_workdir)] == self.local_workdir
        rel_job_dir = job_dir[len(self.local_workdir) + 1 :]

        remote_url = "{}/{}".format(self.remote_url, rel_job_dir)
        local_job_dir = "{}/{}".format(self.local_workdir, rel_job_dir)
        local_wrapper_path = os.path.join(local_job_dir, "wrapper.sh")

        source_and_dest = list(resolver_state.files_to_upload_and_download)
        source_and_dest.append((local_wrapper_path, "wrapper.sh"))

        if outputs is not None:
            local_write_results_path = os.path.join(local_job_dir, "write_results.py")
            source_and_dest += [(local_write_results_path, "write_results.py")]
            run_stmts += ["{} write_results.py".format(self.python_path)]
            with open(local_write_results_path, "wt") as fd:
                fd.write(
                    "import json\n"
                    "results = {}\n"
                    "fd = open('results.json', 'wt')\n"
                    "fd.write(json.dumps(results))\n"
                    "fd.close()\n".format(repr(dict(outputs=outputs)))
                )

        write_wrapper_script(local_wrapper_path, None, prologue, run_stmts, None)

        remote = helper.new_remote(remote_url, local_job_dir,)
        cas_remote = helper.new_remote(self.cas_remote_url, local_job_dir,)
        for _, dest in source_and_dest:
            assert dest[0] != "/"

        pull_map = push_to_cas_with_pullmap(
            cas_remote, source_and_dest, resolver_state.files_to_download
        )
        results_path = make_results_path(self.cas_remote_url, pull_map)
        if self.recycle_past_runs and remote.exists(results_path):
            return load_existing_results(id, remote, results_path, name)

        command = (
            "{helper_path} exec --uploadresults {results_path} "
            "-u retcode.json "
            "-u stdout.txt "
            "-u stderr.txt "
            "-o stdout.txt "
            "-e stderr.txt "
            "-r retcode.json "
            "-f {pull_map} "
            "--stage {stage_dir} "
            "{remote_url} "
            "{cas_remote_url} "
            ". "
            "bash wrapper.sh".format(
                results_path=results_path,
                helper_path=self.helper_path.apply(parameters=executor_parameters),
                remote_url=remote_url,
                pull_map=pull_map,
                cas_remote_url=self.cas_remote_url,
                stage_dir=".",
            )
        )

        #### start of local execution of delegate
        stdout_path = os.path.abspath(os.path.join(job_dir, "delegate.log"))

        full_command = self.run_command_template.apply(
            COMMAND=command, JOB=rel_job_dir, parameters=executor_parameters
        ).strip()

        stdout_file_obj = open(stdout_path, "wt")
        bash_cmd = "exec {full_command}".format(full_command=full_command)
        close_fds = True

        log.warning("executing: %s", bash_cmd)

        assert_is_single_command(bash_cmd)

        # create child in new process group so ctrl-c doesn't kill child process
        returncode = subprocess.call(
            ["bash", "-c", bash_cmd],
            close_fds=close_fds,
            preexec_fn=os.setsid,
            cwd=job_dir,
            stdout=stdout_file_obj,
            stderr=subprocess.STDOUT,
        )
        stdout_file_obj.close()

        with open(stdout_path, "rt") as fd:
            output = fd.read()

        if returncode != 0:
            log.error(
                'Failed to run %s due to non-zero error code (%d) when running "%s". Log from the command:\n%s\n',
                name,
                returncode,
                full_command,
                output,
            )
            return FailedExecutionStub(
                id, "Could not launch delegate runner", name, job_dir=job_dir
            )

        x_job_id = self._extract_job_id(output)

        with open(os.path.join(job_dir, "description.txt"), "w") as fd:
            fd.write(desc_name)

        file_fetcher = self._mk_file_fetcher(remote)
        proc = ExternProc(
            x_job_id,
            self.check_cmd_template,
            self.is_running_pattern,
            self.terminate_cmd_template,
            self.complete_cmd_template,
            executor_parameters,
            stdout_path,
        )
        return DelegateExecution(
            name,
            id,
            job_dir,
            proc,
            outputs,
            (stdout_path, None),
            desc_name,
            remote,
            file_fetcher,
            self.label,
            results_path,
            executor_parameters,
            stdout_path,
        )

    def _mk_file_fetcher(self, remote):
        def file_fetcher(name, destination):
            remote.download(name, destination, ignoreMissing=True, skip_existing=False)

        return file_fetcher


class RemoteResolveState(ResolveState):
    def __init__(
        self,
        files_to_upload_and_download: List[Tuple[str, str]],
        files_to_download: List[Any],
    ) -> None:
        self.files_to_upload_and_download = files_to_upload_and_download
        self.files_to_download = files_to_download

    def add_script(self, filename):
        self.files_to_upload_and_download.append((filename, os.path.basename(filename)))


class DelegateExecClient:
    def __init__(
        self,
        resources: Dict[str, float],
        label: str,
        local_workdir: str,
        remote_url: str,
        cas_remote_url: str,
        helper_path: str,
        command_template: TemplatePartial,
        python_path: str,
        recycle_past_runs: bool,
    ) -> None:
        self.resources = resources
        self.helper_path = helper_path
        self.local_workdir = local_workdir
        self.remote_url = remote_url
        self.command_template = command_template
        self.cas_remote_url = cas_remote_url
        self.python_path = python_path
        self.label = label
        self.recycle_past_runs = recycle_past_runs

    def reattach(self, external_ref: str) -> DelegateExecution:
        print("reattach", repr(external_ref))
        d = json.loads(external_ref)
        remote = helper.new_remote(d["remote_url"], d["local_job_dir"],)
        file_fetcher = self._mk_file_fetcher(remote)
        return DelegateExecution(
            d["transform"],
            d["id"],
            d["job_dir"],
            PidProcStub(d["pid"]),
            d["outputs"],
            d["captured_stdouts"],
            d["desc_name"],
            remote,
            file_fetcher,
            d["label"],
            d["results_path"],
            d["executor_parameters"],
            d["delegate_log"],
        )

    def preprocess_inputs(
        self, resolver: Resolver, inputs: Tuple[BoundInput]
    ) -> Tuple[Dict[str, Dict[str, str]], RemoteResolveState]:
        (
            files_to_download,
            files_to_upload_and_download,
            result,
        ) = process_inputs_for_remote_exec(inputs)
        return (
            result,
            RemoteResolveState(files_to_upload_and_download, files_to_download),
        )

    def exec_script(
        self,
        name: str,
        id: int,
        job_dir: str,
        run_stmts: List[str],
        outputs: Optional[List[PropsType]],
        capture_output: bool,
        prologue: str,
        desc_name: str,
        resolver_state: ResolveState,
        resources: Dict[str, float],
        watch_regex,
        executor_parameters: Dict[str, str],
    ) -> DelegateExecution:
        assert isinstance(resolver_state, ResolveState)

        assert (
            watch_regex is None
        ), "delegated executors cannot watch logs, watch-regex not allowed"

        assert job_dir[: len(self.local_workdir)] == self.local_workdir
        rel_job_dir = job_dir[len(self.local_workdir) + 1 :]

        remote_url = "{}/{}".format(self.remote_url, rel_job_dir)
        local_job_dir = "{}/{}".format(self.local_workdir, rel_job_dir)
        local_wrapper_path = os.path.join(local_job_dir, "wrapper.sh")

        source_and_dest = list(resolver_state.files_to_upload_and_download)
        source_and_dest.append((local_wrapper_path, "wrapper.sh"))

        if outputs is not None:
            local_write_results_path = os.path.join(local_job_dir, "write_results.py")
            source_and_dest += [(local_write_results_path, "write_results.py")]
            run_stmts += ["{} write_results.py".format(self.python_path)]
            with open(local_write_results_path, "wt") as fd:
                fd.write(
                    "import json\n"
                    "results = {}\n"
                    "fd = open('results.json', 'wt')\n"
                    "fd.write(json.dumps(results))\n"
                    "fd.close()\n".format(repr(dict(outputs=outputs)))
                )

        write_wrapper_script(local_wrapper_path, None, prologue, run_stmts, None)

        remote = helper.new_remote(remote_url, local_job_dir,)
        cas_remote = helper.new_remote(self.cas_remote_url, local_job_dir,)
        for _, dest in source_and_dest:
            assert dest[0] != "/"

        pull_map = push_to_cas_with_pullmap(
            cas_remote, source_and_dest, resolver_state.files_to_download
        )
        results_path = make_results_path(self.cas_remote_url, pull_map)
        if self.recycle_past_runs and remote.exists(results_path):
            return load_existing_results(id, remote, results_path, name)

        command = (
            "{helper_path} exec --uploadresults {results_path} "
            "-u retcode.json "
            "-u stdout.txt "
            "-u stderr.txt "
            "-o stdout.txt "
            "-e stderr.txt "
            "-r retcode.json "
            "-f {pull_map} "
            "--stage {stage_dir} "
            "{remote_url} "
            "{cas_remote_url} "
            ". "
            "bash wrapper.sh".format(
                results_path=results_path,
                helper_path=self.helper_path,
                remote_url=remote_url,
                pull_map=pull_map,
                cas_remote_url=self.cas_remote_url,
                stage_dir=".",
            )
        )

        #### start of local execution of delegate
        stdout_path = os.path.abspath(os.path.join(job_dir, "delegate.log"))

        full_command = self.command_template.apply(
            COMMAND=command, JOB=rel_job_dir, parameters=executor_parameters
        ).strip()

        assert_is_single_command(full_command)

        if capture_output:
            bash_cmd = "exec {full_command} > {stdout_path} 2&>1".format(**locals())
            captured_stdouts = [stdout_path]
            close_fds = True
        else:
            bash_cmd = "exec {full_command}".format(**locals())
            captured_stdouts = []
            close_fds = False

        log.warning("executing: %s", bash_cmd)

        # create child in new process group so ctrl-c doesn't kill child process
        proc = subprocess.Popen(
            ["bash", "-c", bash_cmd],
            close_fds=close_fds,
            preexec_fn=os.setsid,
            cwd=job_dir,
        )

        # breakpoint()

        with open(os.path.join(job_dir, "description.txt"), "w") as fd:
            fd.write(desc_name)

        file_fetcher = self._mk_file_fetcher(remote)
        return DelegateExecution(
            name,
            id,
            job_dir,
            proc,
            outputs,
            captured_stdouts,
            desc_name,
            remote,
            file_fetcher,
            self.label,
            results_path,
            executor_parameters,
            stdout_path,
        )

    def _mk_file_fetcher(self, remote: Remote) -> Callable:
        def file_fetcher(name, destination):
            remote.download(name, destination, ignoreMissing=True, skip_existing=False)

        return file_fetcher


def _resolve_filenames(remote: Remote, artifact: PropsType) -> PropsType:
    new_artifact = dict()
    for k, v in artifact.items():
        if type(v) == dict and "$filename" in v:
            v = {"$file_url": remote.remote_url + "/" + v["$filename"]}
        new_artifact[k] = v

    log.debug("translated %r -> %r", artifact, new_artifact)

    return new_artifact


def _log_local_failure(captured_stdouts):
    if captured_stdouts != None:
        log_job_output(captured_stdouts[0], "stdout")
        log_job_output(captured_stdouts[1], "stderr")


def _log_remote_failure(file_fetch, msg):
    log.error(msg)

    with tempfile.NamedTemporaryFile() as tmpstderr:
        with tempfile.NamedTemporaryFile() as tmpstdout:
            log.info("Fetching error and output logs for failed job's 'helper'")
            helper_stderr_path = file_fetch("helper_stderr.txt", tmpstderr.name)
            helper_stdout_path = file_fetch("helper_stdout.txt", tmpstdout.name)

            log_job_output(tmpstderr.name, helper_stderr_path)
            log_job_output(tmpstdout.name, helper_stdout_path)

    with tempfile.NamedTemporaryFile() as tmpstderr:
        with tempfile.NamedTemporaryFile() as tmpstdout:
            log.info("Fetching error and output logs for failed job")
            stderr_path = file_fetch("stderr.txt", tmpstderr.name)
            stdout_path = file_fetch("stdout.txt", tmpstdout.name)

            log_job_output(tmpstderr.name, stderr_path)
            log_job_output(tmpstdout.name, stdout_path)


def assert_is_single_command(command):
    # A source of confusion is commands which span multiple lines but are missing backslashes
    # make sure that all newlines have a preceeding "\"
    for line in command.split("\n")[:-1]:
        if len(line) == 0 or line[-1] != "\\":
            raise Exception(
                f'The command {command} would likely not work as expected because it spans multiple lines and is missing "\\" at the end of the lines. Specifically the line {repr(line)} ends with {repr(line[-1])}'
            )


def assert_has_only_props(
    properties: PropsType, names: List[str], optional: List[str] = [],
) -> None:
    keys = set(properties.keys())
    keys.difference_update(optional)
    assert sorted(names) == sorted(names), "Expected properties: {}, but got {}".format(
        sorted(names), sorted(properties.keys())
    )


def create_client(name, config, properties, jinja2_env):
    def _make_template(text):
        return TemplatePartial(jinja2_env, config, text)

    resources = {"slots": 1}
    for k, v in properties.get("resources", {}).items():
        resources[k] = float(v)
    type = properties.get("type")

    if type == "local":
        assert_has_only_props(properties, ["type", "resources"])
        return LocalExecClient(resources)
    elif type == "delegate":
        assert_has_only_props(
            properties,
            ["type", "resources", "HELPER_PATH", "COMMAND_TEMPLATE", "label"],
            optional=["REUSE_PAST_RUNS"],
        )

        reuse_past_runs_str = properties.get("REUSE_PAST_RUNS", "true").lower()
        assert reuse_past_runs_str in ["true", "false"]
        reuse_past_runs = reuse_past_runs_str == "true"

        return DelegateExecClient(
            resources,
            properties["label"],
            config["WORKING_DIR"],
            get_staging_url(config) + "/exec-results/" + config["EXECUTION_ID"],
            get_staging_url(config),
            properties["HELPER_PATH"],
            _make_template(properties["COMMAND_TEMPLATE"]),
            config.get("PYTHON_PATH", "python"),
            reuse_past_runs,
        )
    elif type == "async-delegate":
        assert_has_only_props(
            properties,
            [
                "type",
                "resources",
                "HELPER_PATH",
                "COMMAND_TEMPLATE",
                "CHECK_COMMAND_TEMPLATE",
                "IS_RUNNING_PATTERN",
                "label",
                "TERMINATE_CMD_TEMPLATE",
                "JOB_ID_PATTERN",
                "COMPLETED_CMD_TEMPLATE",
            ],
            optional=["REUSE_PAST_RUNS", "COMPLETED_CMD_TEMPLATE"],
        )

        reuse_past_runs_str = properties.get("REUSE_PAST_RUNS", "true").lower()
        assert reuse_past_runs_str in ["true", "false"]
        reuse_past_runs = reuse_past_runs_str == "true"

        return AsyncDelegateExecClient(
            resources,
            name,
            config["WORKING_DIR"],
            get_staging_url(config) + "/exec-results/" + config["EXECUTION_ID"],
            get_staging_url(config),
            _make_template(properties["HELPER_PATH"]),
            _make_template(properties["COMMAND_TEMPLATE"]),
            config.get("PYTHON_PATH", "python"),
            _make_template(properties["CHECK_COMMAND_TEMPLATE"]),
            properties["IS_RUNNING_PATTERN"],
            _make_template(properties["TERMINATE_CMD_TEMPLATE"]),
            _make_template(properties.get("COMPLETED_CMD_TEMPLATE")),
            properties["JOB_ID_PATTERN"],
            reuse_past_runs,
        )
    else:
        raise Exception(
            f"Unrecognized executor type: {type} (expected: 'local', 'delegate' or 'async-delegate')"
        )
