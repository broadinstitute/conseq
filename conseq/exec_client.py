import collections
import datetime
import json
import logging
import os
import re
import shutil
import subprocess
import sys
from subprocess import Popen
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from conseq import debug_log
from conseq import dep
from conseq import helper
from conseq.dep import Jobs, Obj
from conseq.helper import Remote
from conseq.xref import Resolver

_basestring = str

log = logging.getLogger(__name__)


class PidProcStub:
    def __init__(self, pid: int) -> None:
        self.pid = pid

    def __repr__(self):
        return "<PidProcStub pid:{}>".format(self.pid)

    def poll(self) -> int:
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


def is_valid_value(v):
    if isinstance(v, dict):
        return len(v) == 1 and (("$filename" in v) or ("$value" in v))
    return isinstance(v, str)


def _tail_file(filename, line_count=20, out=sys.stderr):
    if not os.path.exists(filename):
        log.error("Cannot tail {} because no such file exists".format(filename))
        return

    with open(filename, "rt") as fd:
        fd.seek(0, 2)
        file_len = fd.tell()
        # read at most, the last 100k of the file
        fd.seek(max(0, file_len - 100000), 0)
        lines = fd.read().split("\n")
        for line in lines[-line_count:]:
            print(line)
    out.flush()


def log_job_output(stdout_path, stderr_path, line_count=20, stdout_path_to_print=None, stderr_path_to_print=None):
    if stdout_path_to_print is None:
        stdout_path_to_print = stdout_path
    if stderr_path_to_print is None:
        stderr_path_to_print = stderr_path

    if stdout_path is not None:
        log.error("Dumping last {} lines of stdout ({})".format(line_count, stdout_path_to_print))
        _tail_file(stdout_path)

    if stderr_path is not None:
        log.error("Dumping last {} lines of stderr ({})".format(line_count, stderr_path_to_print))
        _tail_file(stderr_path)


class FailedExecutionStub:
    def __init__(self, id, message):
        self.id = id
        self.message = message

    def get_external_id(self):
        return "FailedExecutionStub:{}".format(self.id)

    def get_completion(self):
        log.error(self.message)
        return self.message, None


class SuccessfulExecutionStub:
    def __init__(self, id, outputs):
        self.id = id
        self.outputs = outputs

    def get_external_id(self):
        return "SuccessfulExecutionStub:{}".format(self.id)

    def get_completion(self):
        return None, self.outputs


# Execution(name, id, job_dir, ReportSuccessProcStub(), outputs, None, desc_name)
#         retcode_file = os.path.join(job_dir, "retcode.txt")
#         with open(retcode_file, "wt") as fd:
#             fd.write("0")

# returns None if no errors were found.  Else returns a string with the error to report to the user
def validate_result_json_obj(obj, types):
    if not ("outputs" in obj):
        return "Missing 'outputs' in object"

    outputs = obj['outputs']
    if not isinstance(outputs, list):
        return "Expected outputs to be a list"

    for o in outputs:
        if not isinstance(o, dict):
            return "Expected members of outputs to by dictionaries"

        for k, v in o.items():
            if isinstance(v, dict):
                if not (len(v) == 1 and "$filename" in v):
                    return "Expected a dict value to only have a $filename key"
                if not isinstance(v["$filename"], _basestring):
                    return "Expected filename to be a string"
            elif isinstance(v, _basestring):
                return "Expected value for property {} to be a string".format(k)

        # now validate against defined types
        if not ("type" in o):
            continue

        type_name = o["type"]
        if not (type_name in o):
            continue

        type = types[type_name]
        missing = []
        for prop in type.properties:
            if not (prop in o):
                missing.append(prop)
        if len(missing):
            return "Artifact had type {} but was missing: {}".format(type_name, ", ".join(missing))

    return None


class Execution:
    def __init__(self, transform: str, id: int, job_dir: str, proc: Union[PidProcStub, Popen],
                 outputs: List[Dict[str, Union[str, Dict[str, str]]]],
                 captured_stdouts: Union[List[str], Tuple[str, str]], desc_name: str) -> None:
        self.transform = transform
        self.id = id
        self.proc = proc
        self.job_dir = job_dir
        self.outputs = outputs
        self.captured_stdouts = captured_stdouts
        self.desc_name = desc_name
        assert job_dir != None

    def _resolve_filenames(self, props):
        props_copy = {}
        for k, v in props.items():
            if isinstance(v, dict) and "$filename" in v:
                full_filename = os.path.join(self.job_dir, v["$filename"])
                if not os.path.exists(full_filename):
                    raise Exception("Attempted to publish results which referenced file that did not exist: {}".format(
                        full_filename))
                v = {"$filename": full_filename}
            props_copy[k] = v
        return props_copy

    def get_state_label(self) -> str:
        return "local-run"

    def get_external_id(self) -> str:
        d = dict(transform=self.transform, id=self.id, job_dir=self.job_dir, pid=self.proc.pid, outputs=self.outputs,
                 captured_stdouts=self.captured_stdouts, desc_name=self.desc_name)
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

    def get_completion(self) -> Union[
        Tuple[None, List[Dict[str, Union[str, Dict[str, str]]]]], Tuple[None, List[Any]], Tuple[None, None]]:
        failure, outputs = self._get_completion()
        if failure is not None:
            self._log_failure(failure)
        return failure, outputs

    def _get_completion(self) -> Union[Tuple[None, List[Any]], Tuple[None, None]]:
        retcode = self.proc.poll()

        if retcode == None:
            return None, None

        if retcode != 0:
            return ("shell command failed with {}".format(retcode), None)

        retcode_file = os.path.join(self.job_dir, "retcode.txt")
        try:
            with open(retcode_file) as fd:
                retcode = int(fd.read())
                if retcode != 0:
                    return "failed with {}".format(retcode), None
        except FileNotFoundError:
            return "No retcode file {}".format(retcode_file), None

        if self.outputs != None:
            results = {"outputs": self.outputs}
        else:
            if not os.path.exists(self.results_path):
                return ("rule {} completed successfully, but no results.json file written to working directory".format(
                    self.transform), None)

            with open(self.results_path) as fd:
                results = json.load(fd)
                # quick verify that results is well formed
                error = None
                if not isinstance(results, dict):
                    error = "results.json did not contain a valid object"
                else:
                    artifacts = results.get('outputs', None)
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
                                        error = "artifact's key/values must both be strings"
                                        break
                                if error is not None:
                                    break
                if error:
                    return (error, None)

        log.info("Rule {} completed ({}). Results: {}".format(self.transform, self.job_dir, results))
        outputs = [self._resolve_filenames(o) for o in results['outputs']]

        # print summary of output files with full paths
        files_written = []
        for output in outputs:
            for value in output.values():
                if isinstance(value, dict) and "$filename" in value:
                    files_written.append(value["$filename"])
        if len(files_written):
            log.warning("Rule %s wrote the following files:\n%s", self.transform,
                        "\n".join(["\t" + x for x in files_written]))

        return None, outputs


class DelegateExecution(Execution):
    def __init__(self, transform: str, id: int, job_dir: str, proc: Union[PidProcStub, Popen],
                 outputs: List[Dict[str, Union[str, Dict[str, str]]]],
                 captured_stdouts: Union[List[str], Tuple[str, str]], desc_name: str, remote: Remote,
                 file_fetcher: Callable, label: str,
                 results_path: str) -> None:
        super(DelegateExecution, self).__init__(transform, id, job_dir, proc, outputs, captured_stdouts, desc_name)
        self.remote = remote
        self.file_fetcher = file_fetcher
        self.label = label
        self._results_path = results_path

    def get_state_label(self) -> str:
        return self.label

    def get_external_id(self) -> str:
        d = dict(transform=self.transform, id=self.id,
                 outputs=self.outputs,
                 captured_stdouts=self.captured_stdouts,
                 desc_name=self.desc_name,
                 remote_url=self.remote.remote_url,
                 job_dir=self.job_dir,
                 local_job_dir=self.job_dir,
                 label=self.label,
                 results_path=self._results_path)
        if hasattr(self.proc, 'pid'):
            d['pid'] = self.proc.pid
        else:
            d['x_job_id'] = self.proc.job_id

        return json.dumps(d)

    def _log_failure(self, msg):
        _log_remote_failure(self.file_fetcher, msg)
        _log_local_failure(self.captured_stdouts)

    def _get_completion(self) -> Union[Tuple[None, List[Dict[str, Union[str, Dict[str, str]]]]], Tuple[None, None]]:
        retcode = self.proc.poll()
        # print("_get_completion -> {}".format(retcode))
        if retcode == None:
            return None, None

        if retcode != 0:
            return ("shell command failed with {}".format(retcode), None)

        log.debug("About to download retcode.json")

        retcode_content = self.remote.download_as_str("retcode.json")
        if retcode_content is not None:
            retcode = json.loads(retcode_content)['retcode']
        else:
            log.debug("got no retcode")
            retcode = None

        if retcode != 0:
            return ("inner shell command failed with {}".format(repr(retcode)), None)

        results_str = self.remote.download_as_str(self._results_path)
        if results_str is None:
            return ("script reported success but results.json is missing!", None)

        results = json.loads(results_str)

        log.info("Rule {} completed ({}). Results: {}".format(self.desc_name, self.job_dir, results))
        assert type(results['outputs']) == list
        outputs = [_resolve_filenames(self.remote, o) for o in results['outputs']]

        return None, outputs


def write_wrapper_script(wrapper_path: str, job_dir: Optional[str], prologue: str, run_stmts: List[str],
                         retcode_path: Optional[str]) -> None:
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
            fd.write("  " + run_stmt + " &\n")
            fd.write("  PID=$!\n")
            fd.write("  wait $PID\n")
            fd.write("  trap - TERM INT\n")
            fd.write("  wait $PID\n")
            fd.write("  EXIT_STATUS=$?\n")
            fd.write("fi\n\n")

        if retcode_path is not None:
            fd.write("echo $EXIT_STATUS > {retcode_path}\n".format(**locals()))


def local_exec_script(name: str, id: int, job_dir: str, run_stmts: List[str], outputs: List[Any], capture_output: bool,
                      prologue: str, desc_name: str) -> Execution:
    stdout_path = os.path.join(job_dir, "stdout.txt")
    stderr_path = os.path.join(job_dir, "stderr.txt")
    # results_path = os.path.join(job_dir, "results.json")

    stdout_path = os.path.abspath(stdout_path)
    stderr_path = os.path.abspath(stderr_path)
    retcode_path = os.path.abspath(os.path.join(job_dir, "retcode.txt"))

    wrapper_path = os.path.join(job_dir, "wrapper.sh")
    write_wrapper_script(wrapper_path, job_dir, prologue, run_stmts, retcode_path)

    if capture_output:
        bash_cmd = "exec bash {wrapper_path} > {stdout_path} 2> {stderr_path}".format(**locals())
        captured_stdouts = (stdout_path, stderr_path)
        close_fds = True
    else:
        bash_cmd = "exec bash {wrapper_path}".format(**locals())
        captured_stdouts = None
        close_fds = False

    # log.info("Starting task in %s", job_dir)
    log.debug("executing: %s", bash_cmd)

    # create child in new process group so ctrl-c doesn't kill child process
    proc = subprocess.Popen(['bash', '-c', bash_cmd], close_fds=close_fds, preexec_fn=os.setsid)

    with open(os.path.join(job_dir, "description.txt"), "w") as fd:
        fd.write(desc_name)

    return Execution(name, id, job_dir, proc, outputs, captured_stdouts, desc_name)


def fetch_urls(obj: Dict[str, Union[str, Dict[str, str]]], resolver: Resolver) -> Dict[str, str]:
    assert isinstance(obj, dict)
    new_obj = {}
    for k, v in obj.items():
        if isinstance(v, dict) and "$file_url" in v:
            url = v["$file_url"]
            filename = resolver.resolve(url)['filename']
            new_obj[k] = filename
        else:
            new_obj[k] = v
    return new_obj


def needs_resolution(obj: Dict[str, Union[str, Dict[str, str]]]) -> bool:
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


def preprocess_xref_inputs(j: Jobs, resolver: Resolver, inputs: Tuple[Tuple[str, Obj]]) -> bool:
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
    pass


class NullResolveState(ResolveState):
    def __init__(self, files_to_copy: List[Any]) -> None:
        self.files_to_copy = files_to_copy

    def add_script(self, script):
        pass


class ExternProc:
    def __init__(self, job_id, check_cmd_template, is_running_pattern, terminate_cmd_template):
        self.job_id = job_id
        self.check_cmd_template = check_cmd_template
        self.is_running_pattern = is_running_pattern
        self.terminate_cmd_template = terminate_cmd_template

    def poll(self):
        check_cmd = self.check_cmd_template.format(job_id=self.job_id)
        output = subprocess.check_output(check_cmd, shell=True)
        output = output.decode("utf8")
        # print("Check_cmd: {}".format(check_cmd))
        m = re.search(self.is_running_pattern, output)
        # print("output={} is_running_pattern={}, m={}".format(repr(output), self.is_running_pattern, m))
        if m is None:
            return 0
        return None

    def terminate(self):
        terminate_cmd = self.terminate_cmd_template.format(job_id=self.job_id)
        log.warning("Executing: %s", terminate_cmd)
        subprocess.check_call(terminate_cmd, shell=True)


# class ReportSuccessProcStub:
#     def __init__(self):
#         self.pid = 10000000
#
#     def poll(self):
#         return 0



class LocalExecClient:
    def __init__(self, resources: Dict[Any, Any]) -> None:
        self.resources = resources

    def reattach(self, external_ref):
        d = json.loads(external_ref)
        return Execution(d['transform'], d['id'], d['job_dir'], PidProcStub(d['pid']), d['outputs'],
                         d['captured_stdouts'], d['desc_name'])

    def preprocess_inputs(self, resolver: Resolver, inputs: Tuple[Tuple[str, Obj]]) -> Tuple[
        Dict[str, Dict[str, str]], NullResolveState]:
        files_to_copy = []

        def resolve(obj_: dep.Obj):
            assert isinstance(obj_, dep.Obj)

            obj = obj_.props
            assert isinstance(obj, dict)

            obj = fetch_urls(obj, resolver)
            obj = flatten_parameters(obj)
            if obj.get("type") == "$fileref":
                destination = obj.get("destination")
                if destination:
                    files_to_copy.append((destination, destination))
            return obj

        result = {}
        for bound_name, obj_or_list in inputs:
            if isinstance(obj_or_list, list) or isinstance(obj_or_list, tuple):
                list_ = obj_or_list
                result[bound_name] = [resolve(obj_) for obj_ in list_]
            else:
                obj_ = obj_or_list
                result[bound_name] = resolve(obj_)

        return result, NullResolveState(files_to_copy)

    def exec_script(self, name: str, id: int, job_dir: str, run_stmts: List[str], outputs: List[Any],
                    capture_output: bool, prologue: str, desc_name: str, resolve_state: NullResolveState,
                    resources: Dict[str, int]) -> Execution:

        for src, dst in resolve_state.files_to_copy:
            shutil.copy(src, os.path.join(job_dir, dst))

        return local_exec_script(name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name)


SgeState = collections.namedtuple("SgeState", ["update_timestamp", "status", "refresh_id"])

SGE_STATUS_SUBMITTED = "submitted"
SGE_STATUS_PENDING = "pending"
SGE_STATUS_RUNNING = "running"
SGE_STATUS_COMPLETE = "complete"
SGE_STATUS_UNKNOWN = "unknown"

import tempfile


def drop_prefix(prefix, value):
    assert value[:len(prefix)] == prefix, "prefix=%r, value=%r" % (prefix, value)
    return value[len(prefix):]


def push_to_cas_with_pullmap(remote: Remote, source_and_dest: List[Tuple[str, str]], url_and_dest: List[Any]) -> str:
    source_and_dest = [(os.path.abspath(source), dest) for source, dest in source_and_dest]
    log.debug("push_to_cas_with_pullmap, filenames: %s", source_and_dest)
    name_mapping = helper.push_to_cas(remote, [source for source, dest in source_and_dest])

    mapping = [dict(remote="{}/{}".format(remote.remote_url, name_mapping[source]), local=dest)
               for source, dest in source_and_dest]

    mapping += [dict(remote=src_url, local=dest)
                for src_url, dest in url_and_dest]

    log.debug("name_mapping: %s", name_mapping)
    log.debug("mapping: %s", mapping)
    for rec in mapping:
        if rec["local"].startswith("/"):
            rec['local'] = os.path.relpath(rec['local'], remote.local_dir)

    debug_log.log_pullmap(mapping)

    mapping_str = json.dumps(dict(mapping=mapping), sort_keys=True)
    log.debug("Mapping str: %s", mapping_str)
    fd = tempfile.NamedTemporaryFile(mode="wt")
    fd.write(mapping_str)
    fd.flush()
    map_name = list(helper.push_to_cas(remote, [fd.name]).values())[0]
    fd.close()

    return "{}/{}".format(remote.remote_url, map_name)


def process_inputs_for_publishing(cas_remote, inputs):
    def resolve(obj_):
        assert isinstance(obj_, dep.Obj)
        obj = obj_.props
        assert isinstance(obj, dict)

        new_obj = {}
        for k, v in obj.items():
            if type(v) == dict and "$filename" in v:
                cur_name = v["$filename"]
                new_url = cas_remote.remote_url + "/" + helper.push_to_cas(cas_remote, [cur_name])[cur_name]
                v = new_url
            elif isinstance(v, dict) and "$file_url" in v:
                v = v["$file_url"]
            elif isinstance(v, dict) and len(v) == 1 and "$value" in v:
                v = v["$value"]
            else:
                assert isinstance(v, str), "Expected value for {} ({}) to be a string but was {}".format(k, repr(v),
                                                                                                         type(v))

            new_obj[k] = v

        return new_obj

    result = {}
    for bound_name, obj_or_list in inputs:
        if isinstance(obj_or_list, list) or isinstance(obj_or_list, tuple):
            list_ = obj_or_list
            result[bound_name] = [resolve(obj_) for obj_ in list_]
        else:
            obj_ = obj_or_list
            result[bound_name] = resolve(obj_)
    log.debug("preprocess_inputs, after inputs: %s", result)

    return result


def process_inputs_for_remote_exec(inputs: Tuple[Tuple[str, Obj]]) -> Tuple[
    List[Any], List[Tuple[str, str]], Dict[str, Dict[str, str]]]:
    log.debug("preprocess_inputs, before inputs: %s", inputs)
    files_to_upload_and_download = []
    files_to_download = []

    def next_file_index():
        return len(files_to_upload_and_download) + len(files_to_download)

    # need to find all files that will be downloaded and update with $filename of what eventual local location will be.
    def resolve(obj_):
        assert isinstance(obj_, dep.Obj)
        obj = obj_.props
        assert isinstance(obj, dict)

        # temporarily using dest prop for filerefs. This works because filerefs only have one file
        # probably need to clean this up eventually
        destination = None
        if obj.get("type") == "$fileref":
            destination = flatten_value(obj.get("destination"))

        new_obj = {}
        for k, v in obj.items():
            if type(v) == dict and "$filename" in v:
                cur_name = v["$filename"]
                # Need to do something to avoid collisions.  Store under working dir?  maybe temp/filename-v
                if destination is None:
                    new_name = "temp/{}.{}".format(os.path.basename(cur_name), next_file_index())
                else:
                    new_name = destination
                files_to_upload_and_download.append((cur_name, new_name))
                v = new_name
            elif isinstance(v, dict) and "$file_url" in v:
                cur_name = v["$file_url"]
                if destination is None:
                    new_name = "temp/{}.{}".format(os.path.basename(cur_name), next_file_index())
                else:
                    new_name = destination
                files_to_download.append((cur_name, new_name))
                v = new_name
            elif isinstance(v, dict) and len(v) == 1 and "$value" in v:
                v = v["$value"]
            else:
                assert isinstance(v, str), "Expected value for {} ({}) to be a string but was {}".format(k, repr(v),
                                                                                                         type(v))

            new_obj[k] = v

        return new_obj

    result = {}
    for bound_name, obj_or_list in inputs:
        if isinstance(obj_or_list, list) or isinstance(obj_or_list, tuple):
            list_ = obj_or_list
            result[bound_name] = [resolve(obj_) for obj_ in list_]
        else:
            obj_ = obj_or_list
            result[bound_name] = resolve(obj_)
    log.debug("preprocess_inputs, after inputs: %s", result)
    log.debug("files_to_upload_and_download: %s", files_to_upload_and_download)
    log.debug("files_to_download: %s", files_to_download)
    return files_to_download, files_to_upload_and_download, result


def create_publish_exec_client(config):
    return PublishExecClient(config["S3_STAGING_URL"], config['AWS_ACCESS_KEY_ID'],
                             config['AWS_SECRET_ACCESS_KEY'])


def make_results_path(cas_remote_url: str, pull_map_url: str) -> str:
    import hashlib
    hash = hashlib.sha256(pull_map_url.encode("utf-8")).hexdigest()
    return os.path.join(cas_remote_url, "results", hash)


def load_existing_results(id, remote, results_path):
    log.warning("Job appears to have already been run, taking results from %s", results_path)
    results_str = remote.download_as_str(results_path)
    results = json.loads(results_str)
    return SuccessfulExecutionStub(id, outputs=results['outputs'])


class PublishExecClient:
    def __init__(self, cas_remote_url, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
        self.cas_remote = helper.Remote(cas_remote_url, ".", AWS_ACCESS_KEY_ID,
                                        AWS_SECRET_ACCESS_KEY)

    def preprocess_inputs(self, resolver, inputs):
        result = process_inputs_for_publishing(self.cas_remote, inputs)
        return result, None


class AsyncDelegateExecClient:
    def __init__(self, resources, label, local_workdir, remote_url, cas_remote_url, helper_path, run_command_template,
                 python_path, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, check_cmd_template, is_running_pattern,
                 terminate_cmd_template, x_job_id_pattern, recycle_past_runs):
        self.resources = resources
        self.helper_path = helper_path
        self.local_workdir = local_workdir
        self.remote_url = remote_url
        self.run_command_template = run_command_template
        self.cas_remote_url = cas_remote_url
        self.AWS_ACCESS_KEY_ID = AWS_ACCESS_KEY_ID
        self.AWS_SECRET_ACCESS_KEY = AWS_SECRET_ACCESS_KEY
        self.python_path = python_path
        self.label = label
        self.check_cmd_template = check_cmd_template
        self.is_running_pattern = is_running_pattern
        self.terminate_cmd_template = terminate_cmd_template
        self.x_job_id_pattern = x_job_id_pattern
        self.recycle_past_runs = recycle_past_runs

    def _extract_job_id(self, output):
        m = re.match(self.x_job_id_pattern, output)
        if m is None:
            raise Exception("Pattern {} could not be found in {}".format(self.x_job_id_pattern, output))
        return m.group(1)

    def reattach(self, external_ref):
        d = json.loads(external_ref)
        remote = helper.Remote(d['remote_url'], d['local_job_dir'], self.AWS_ACCESS_KEY_ID, self.AWS_SECRET_ACCESS_KEY)
        file_fetcher = self._mk_file_fetcher(remote)
        proc = ExternProc(d['x_job_id'], self.check_cmd_template, self.is_running_pattern, self.terminate_cmd_template)
        return DelegateExecution(d['transform'], d['id'], d['job_dir'], proc, d['outputs'], d['captured_stdouts'],
                                 d['desc_name'], remote, file_fetcher, d['label'], d['results_path'])

    def preprocess_inputs(self, resolver, inputs):
        files_to_download, files_to_upload_and_download, result = process_inputs_for_remote_exec(inputs)
        return result, RemoteResolveState(files_to_upload_and_download, files_to_download)

    def exec_script(self, name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name, resolver_state,
                    resources):
        mem_in_mb = resources.get("mem", 1000)
        assert job_dir[:len(self.local_workdir)] == self.local_workdir
        rel_job_dir = job_dir[len(self.local_workdir) + 1:]

        remote_url = "{}/{}".format(self.remote_url, rel_job_dir)
        local_job_dir = "{}/{}".format(self.local_workdir, rel_job_dir)
        local_wrapper_path = os.path.join(local_job_dir, "wrapper.sh")

        source_and_dest = list(resolver_state.files_to_upload_and_download)
        source_and_dest.append((local_wrapper_path, "wrapper.sh"))

        if outputs is not None:
            local_write_results_path = os.path.join(local_job_dir, 'write_results.py')
            source_and_dest += [(local_write_results_path, "write_results.py")]
            run_stmts += ["{} write_results.py".format(self.python_path)]
            with open(local_write_results_path, "wt") as fd:
                fd.write("import json\n"
                         "results = {}\n"
                         "fd = open('results.json', 'wt')\n"
                         "fd.write(json.dumps(results))\n"
                         "fd.close()\n".format(repr(dict(outputs=outputs))))

        write_wrapper_script(local_wrapper_path, None, prologue, run_stmts, None)

        remote = helper.Remote(remote_url, local_job_dir, self.AWS_ACCESS_KEY_ID, self.AWS_SECRET_ACCESS_KEY)
        cas_remote = helper.Remote(self.cas_remote_url, local_job_dir, self.AWS_ACCESS_KEY_ID,
                                   self.AWS_SECRET_ACCESS_KEY)
        for _, dest in source_and_dest:
            assert dest[0] != '/'

        pull_map = push_to_cas_with_pullmap(cas_remote, source_and_dest, resolver_state.files_to_download)
        results_path = make_results_path(self.cas_remote_url, pull_map)
        if self.recycle_past_runs and remote.exists(results_path):
            return load_existing_results(id, remote, results_path)

        command = "{helper_path} exec --uploadresults {results_path} " \
                  "-u retcode.json " \
                  "-u stdout.txt " \
                  "-u stderr.txt " \
                  "-o stdout.txt " \
                  "-e stderr.txt " \
                  "-r retcode.json " \
                  "-f {pull_map} " \
                  "--stage {stage_dir} " \
                  "{remote_url} " \
                  "{cas_remote_url} " \
                  ". " \
                  "bash wrapper.sh".format(results_path=results_path,
                                           helper_path=self.helper_path,
                                           remote_url=remote_url,
                                           pull_map=pull_map,
                                           cas_remote_url=self.cas_remote_url,
                                           stage_dir=".")

        #### start of local execution of delegate
        stdout_path = os.path.abspath(os.path.join(job_dir, "delegate.log"))

        full_command = self.run_command_template.format(COMMAND=command, JOB=rel_job_dir).strip()
        bash_cmd = "exec {full_command} > {stdout_path} 2>&1".format(full_command=full_command, stdout_path=stdout_path)
        close_fds = True

        log.warning("executing: %s", bash_cmd)

        # create child in new process group so ctrl-c doesn't kill child process
        subprocess.check_call(['bash', '-c', bash_cmd], close_fds=close_fds, preexec_fn=os.setsid, cwd=job_dir)

        with open(stdout_path, "rt") as fd:
            output = fd.read()

        x_job_id = self._extract_job_id(output)

        with open(os.path.join(job_dir, "description.txt"), "w") as fd:
            fd.write(desc_name)

        file_fetcher = self._mk_file_fetcher(remote)
        proc = ExternProc(x_job_id, self.check_cmd_template, self.is_running_pattern, self.terminate_cmd_template)
        return DelegateExecution(name, id, job_dir, proc, outputs, (stdout_path, None), desc_name, remote, file_fetcher,
                                 self.label, results_path)

    def _mk_file_fetcher(self, remote):
        def file_fetcher(name, destination):
            remote.download(name, destination, ignoreMissing=True, skipExisting=False)

        return file_fetcher


class RemoteResolveState(ResolveState):
    def __init__(self, files_to_upload_and_download: List[Tuple[str, str]], files_to_download: List[Any]) -> None:
        self.files_to_upload_and_download = files_to_upload_and_download
        self.files_to_download = files_to_download

    def add_script(self, filename):
        self.files_to_upload_and_download.append((filename, os.path.basename(filename)))


class DelegateExecClient:
    def __init__(self, resources: Dict[str, float], label: str, local_workdir: str, remote_url: str,
                 cas_remote_url: str, helper_path: str, command_template: str,
                 python_path: str, AWS_ACCESS_KEY_ID: str, AWS_SECRET_ACCESS_KEY: str, recycle_past_runs: bool) -> None:
        self.resources = resources
        self.helper_path = helper_path
        self.local_workdir = local_workdir
        self.remote_url = remote_url
        self.command_template = command_template
        self.cas_remote_url = cas_remote_url
        self.AWS_ACCESS_KEY_ID = AWS_ACCESS_KEY_ID
        self.AWS_SECRET_ACCESS_KEY = AWS_SECRET_ACCESS_KEY
        self.python_path = python_path
        self.label = label
        self.recycle_past_runs = recycle_past_runs

    def reattach(self, external_ref: str) -> DelegateExecution:
        print("reattach", repr(external_ref))
        d = json.loads(external_ref)
        remote = helper.Remote(d['remote_url'], d['local_job_dir'], self.AWS_ACCESS_KEY_ID, self.AWS_SECRET_ACCESS_KEY)
        file_fetcher = self._mk_file_fetcher(remote)
        return DelegateExecution(d['transform'], d['id'], d['job_dir'], PidProcStub(d['pid']), d['outputs'],
                                 d['captured_stdouts'], d['desc_name'], remote, file_fetcher, d['label'],
                                 d['results_path'])

    def preprocess_inputs(self, resolver: Resolver, inputs: Tuple[Tuple[str, Obj]]) -> Tuple[
        Dict[str, Dict[str, str]], RemoteResolveState]:
        files_to_download, files_to_upload_and_download, result = process_inputs_for_remote_exec(inputs)
        return result, RemoteResolveState(files_to_upload_and_download, files_to_download)

    def exec_script(self, name: str, id: int, job_dir: str, run_stmts: List[str],
                    outputs: List[Dict[str, Union[str, Dict[str, str]]]], capture_output: bool, prologue: str,
                    desc_name: str, resolver_state: RemoteResolveState,
                    resources: Dict[str, int]) -> DelegateExecution:
        mem_in_mb = resources.get("mem", 1000)
        assert job_dir[:len(self.local_workdir)] == self.local_workdir
        rel_job_dir = job_dir[len(self.local_workdir) + 1:]

        remote_url = "{}/{}".format(self.remote_url, rel_job_dir)
        local_job_dir = "{}/{}".format(self.local_workdir, rel_job_dir)
        local_wrapper_path = os.path.join(local_job_dir, "wrapper.sh")

        source_and_dest = list(resolver_state.files_to_upload_and_download)
        source_and_dest.append((local_wrapper_path, "wrapper.sh"))

        if outputs is not None:
            local_write_results_path = os.path.join(local_job_dir, 'write_results.py')
            source_and_dest += [(local_write_results_path, "write_results.py")]
            run_stmts += ["{} write_results.py".format(self.python_path)]
            with open(local_write_results_path, "wt") as fd:
                fd.write("import json\n"
                         "results = {}\n"
                         "fd = open('results.json', 'wt')\n"
                         "fd.write(json.dumps(results))\n"
                         "fd.close()\n".format(repr(dict(outputs=outputs))))

        write_wrapper_script(local_wrapper_path, None, prologue, run_stmts, None)

        remote = helper.Remote(remote_url, local_job_dir, self.AWS_ACCESS_KEY_ID, self.AWS_SECRET_ACCESS_KEY)
        cas_remote = helper.Remote(self.cas_remote_url, local_job_dir, self.AWS_ACCESS_KEY_ID,
                                   self.AWS_SECRET_ACCESS_KEY)
        for _, dest in source_and_dest:
            assert dest[0] != '/'

        pull_map = push_to_cas_with_pullmap(cas_remote, source_and_dest, resolver_state.files_to_download)
        results_path = make_results_path(self.cas_remote_url, pull_map)
        if self.recycle_past_runs and remote.exists(results_path):
            return load_existing_results(id, remote, results_path)

        command = "{helper_path} exec --uploadresults {results_path} " \
                  "-u retcode.json " \
                  "-u stdout.txt " \
                  "-u stderr.txt " \
                  "-o stdout.txt " \
                  "-e stderr.txt " \
                  "-r retcode.json " \
                  "-f {pull_map} " \
                  "--stage {stage_dir} " \
                  "{remote_url} " \
                  "{cas_remote_url} " \
                  ". " \
                  "bash wrapper.sh".format(results_path=results_path,
                                           helper_path=self.helper_path,
                                           remote_url=remote_url,
                                           pull_map=pull_map,
                                           cas_remote_url=self.cas_remote_url,
                                           stage_dir=".")

        #### start of local execution of delegate
        stdout_path = os.path.abspath(os.path.join(job_dir, "delegate-stdout.txt"))
        stderr_path = os.path.abspath(os.path.join(job_dir, "delegate-stderr.txt"))

        full_command = self.command_template.format(COMMAND=command, JOB=rel_job_dir).strip()
        if capture_output:
            bash_cmd = "exec {full_command} > {stdout_path} 2> {stderr_path}".format(**locals())
            captured_stdouts = (stdout_path, stderr_path)
            close_fds = True
        else:
            bash_cmd = "exec {full_command}".format(**locals())
            captured_stdouts = None
            close_fds = False

        log.warning("executing: %s", bash_cmd)

        # create child in new process group so ctrl-c doesn't kill child process
        proc = subprocess.Popen(['bash', '-c', bash_cmd], close_fds=close_fds, preexec_fn=os.setsid, cwd=job_dir)

        with open(os.path.join(job_dir, "description.txt"), "w") as fd:
            fd.write(desc_name)

        file_fetcher = self._mk_file_fetcher(remote)
        return DelegateExecution(name, id, job_dir, proc, outputs, captured_stdouts, desc_name, remote, file_fetcher,
                                 self.label, results_path)

    def _mk_file_fetcher(self, remote: Remote) -> Callable:
        def file_fetcher(name, destination):
            remote.download(name, destination, ignoreMissing=True, skipExisting=False)

        return file_fetcher


def _resolve_filenames(remote: Remote, artifact: Dict[str, Union[str, Dict[str, str]]]) -> Dict[
    str, Union[str, Dict[str, str]]]:
    new_artifact = dict()
    for k, v in artifact.items():
        if type(v) == dict and "$filename" in v:
            v = {"$file_url": remote.remote_url + "/" + v["$filename"]}
        new_artifact[k] = v

    log.debug("translated %r -> %r", artifact, new_artifact)

    return new_artifact


def _log_local_failure(captured_stdouts):
    if captured_stdouts != None:
        log_job_output(captured_stdouts[0], captured_stdouts[1])


def _log_remote_failure(file_fetch, msg):
    log.error(msg)

    with tempfile.NamedTemporaryFile() as tmpstderr:
        with tempfile.NamedTemporaryFile() as tmpstdout:
            log.info("Fetching error and output logs for failed job's 'helper'")
            helper_stderr_path = file_fetch("helper_stderr.txt", tmpstderr.name)
            helper_stdout_path = file_fetch("helper_stdout.txt", tmpstdout.name)
            log_job_output(tmpstdout.name, tmpstderr.name, stdout_path_to_print=helper_stderr_path,
                           stderr_path_to_print=helper_stdout_path)

    with tempfile.NamedTemporaryFile() as tmpstderr:
        with tempfile.NamedTemporaryFile() as tmpstdout:
            log.info("Fetching error and output logs for failed job")
            stderr_path = file_fetch("stderr.txt", tmpstderr.name)
            stdout_path = file_fetch("stdout.txt", tmpstdout.name)
            log_job_output(tmpstdout.name, tmpstderr.name, stdout_path_to_print=stdout_path,
                           stderr_path_to_print=stderr_path)


def assert_has_only_props(properties: Dict[str, Union[str, Dict[str, str]]], names: List[str],
                          optional: List[str] = []) -> None:
    keys = set(properties.keys())
    keys.difference_update(optional)
    assert keys == set(names), "Expected properties: {}, but got {}".format(names, properties.keys())


def create_client(name, config, properties):
    resources = {"slots": 1}
    for k, v in properties.get("resources", {}).items():
        resources[k] = float(v)
    type = properties.get('type')

    if type == "local":
        assert_has_only_props(properties, ["type", "resources"])
        return LocalExecClient(resources)
    elif type == "delegate":
        assert_has_only_props(properties, ["type", "resources", "HELPER_PATH", "COMMAND_TEMPLATE", "label"],
                              optional=["REUSE_PAST_RUNS"])

        reuse_past_runs_str = properties.get("REUSE_PAST_RUNS", "true").lower()
        assert reuse_past_runs_str in ['true', 'false']
        reuse_past_runs = reuse_past_runs_str == "true"

        return DelegateExecClient(resources, properties['label'], config["WORKING_DIR"],
                                  config["S3_STAGING_URL"] + "/exec-results/" + config["EXECUTION_ID"], config["S3_STAGING_URL"],
                                  properties["HELPER_PATH"], properties["COMMAND_TEMPLATE"],
                                  config.get("PYTHON_PATH", "python"), config["AWS_ACCESS_KEY_ID"],
                                  config["AWS_SECRET_ACCESS_KEY"], reuse_past_runs)
    elif type == "async-delegate":
        assert_has_only_props(properties,
                              ["type", "resources", "HELPER_PATH", "COMMAND_TEMPLATE", "CHECK_COMMAND_TEMPLATE",
                               "IS_RUNNING_PATTERN", "label", "TERMINATE_CMD_TEMPLATE", "JOB_ID_PATTERN"],
                              optional=["REUSE_PAST_RUNS"])

        reuse_past_runs_str = properties.get("REUSE_PAST_RUNS", "true").lower()
        assert reuse_past_runs_str in ['true', 'false']
        reuse_past_runs = reuse_past_runs_str == "true"

        return AsyncDelegateExecClient(resources, properties['label'], config["WORKING_DIR"],
                                       config["S3_STAGING_URL"] + "/exec-results/" + config["EXECUTION_ID"],
                                       config["S3_STAGING_URL"],
                                       properties["HELPER_PATH"], properties["COMMAND_TEMPLATE"],
                                       config.get("PYTHON_PATH", "python"), config["AWS_ACCESS_KEY_ID"],
                                       config["AWS_SECRET_ACCESS_KEY"], properties["CHECK_COMMAND_TEMPLATE"],
                                       properties["IS_RUNNING_PATTERN"], properties["TERMINATE_CMD_TEMPLATE"],
                                       properties["JOB_ID_PATTERN"], reuse_past_runs)
    else:
        raise Exception("Unrecognized exec-profile 'type': {}".format(type))
