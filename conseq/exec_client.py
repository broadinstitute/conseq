import os
import logging
import subprocess
from conseq import dep
import json
import datetime
import xml.etree.ElementTree as ETree
import re

from conseq import helper
import six

if six.PY2:
    _basestring = (str, unicode)
else:
    _basestring = str

log = logging.getLogger(__name__)

def is_valid_value(v):
    if isinstance(v, dict):
      return len(v) == 1 and (("$filename" in v) or ("$value" in v))
    return isinstance(v, str)
       

def _tail_file(filename, line_count=20):
    if not os.path.exists(filename):
        log.error("Cannot tail {} because no such file exists".format(filename))
        return

    with open(filename, "rt") as fd:
        fd.seek(0, 2)
        file_len = fd.tell()
        # read at most, the last 100k of the file
        fd.seek(max(0, file_len-100000), 0)
        lines = fd.read().split("\n")
        for line in lines[-line_count:]:
            print(line)

def log_job_output(stdout_path, stderr_path, line_count=20, stdout_path_to_print=None, stderr_path_to_print=None):
    if stdout_path_to_print is None:
        stdout_path_to_print = stdout_path
    if stderr_path_to_print is None:
        stderr_path_to_print = stderr_path

    log.error("Dumping last {} lines of stdout ({})".format(line_count, stdout_path_to_print))
    _tail_file(stdout_path)
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
    def __init__(self, transform, id, job_dir, proc, outputs, captured_stdouts, desc_name):
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
                    raise Exception("Attempted to publish results which referenced file that did not exist: {}".format(full_filename))
                v = {"$filename": full_filename}
            props_copy[k] = v
        return props_copy

    def get_state_label(self):
        return "local-run"

    def get_external_id(self):
        d = dict(transform = self.transform, id = self.id, job_dir = self.job_dir, pid = self.proc.pid, outputs = self.outputs, captured_stdouts=self.captured_stdouts, desc_name = self.desc_name)
        return json.dumps(d)

    def cancel(self):
        log.warn("Killing pid %s (%s)", self.proc.pid, self.desc_name)
        self.proc.terminate()

    @property
    def results_path(self):
        return os.path.join(self.job_dir, "results.json")

    def _log_failure(self, failure):
        log.error("Task failed %s: %s", self.desc_name, failure)
        if self.captured_stdouts != None:
            log_job_output(self.captured_stdouts[0], self.captured_stdouts[1])

    def get_completion(self):
        failure, outputs = self._get_completion()
        if failure is not None:
            self._log_failure(failure)
        return failure, outputs

    def _get_completion(self):
        retcode = self.proc.poll()

        if retcode == None:
            return None, None

        if retcode != 0:
            return("shell command failed with {}".format(retcode), None)

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
                return("rule {} completed successfully, but no results.json file written to working directory".format(self.transform), None)

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
            log.warn("Rule %s wrote the following files:\n%s", self.transform, "\n".join(["\t"+x for x in files_written]))

        return None, outputs

class DelegateExecution(Execution):
    def __init__(self, transform, id, job_dir, proc, outputs, captured_stdouts, desc_name, remote, file_fetcher):
        super(DelegateExecution, self).__init__(transform, id, job_dir, proc, outputs, captured_stdouts, desc_name)
        self.remote = remote
        self.file_fetcher = file_fetcher

    def _log_failure(self, msg):
        _log_remote_failure(self.file_fetcher, msg)

    def _get_completion(self):
        retcode = self.proc.poll()

        if retcode == None:
            return None, None

        if retcode != 0:
            return("shell command failed with {}".format(retcode), None)

        log.debug("About to download retcode.json")

        retcode_content = self.remote.download_as_str("retcode.json")
        if retcode_content is not None:
            retcode = json.loads(retcode_content)['retcode']
        else:
            log.debug("got no retcode")
            retcode = None

        if retcode != 0:
            return("inner shell command failed with {}".format(repr(retcode)), None)

        results_str = self.remote.download_as_str("results.json")
        if results_str is None:
            return("script reported success but results.json is missing!", None)

        results = json.loads(results_str)

        log.info("Rule {} completed ({}). Results: {}".format(self.desc_name, self.job_dir, results))
        assert type(results['outputs']) == list
        outputs = [_resolve_filenames(self.remote, o) for o in results['outputs']]

        return None, outputs

def write_wrapper_script(wrapper_path, job_dir, prologue, run_stmts, retcode_path):
    with open(wrapper_path, "wt") as fd:
        fd.write("set -ex\n")
        if job_dir is not None:
            job_dir = os.path.abspath(job_dir)
            fd.write("cd {job_dir}\n".format(**locals()))

        fd.write(prologue+"\n")

        fd.write("EXIT_STATUS=0\n")
        for run_stmt in run_stmts:
            fd.write("if [ $EXIT_STATUS == 0 ]; then\n")
            # based on http://veithen.github.io/2014/11/16/sigterm-propagation.html to propagate killing of child proc if this proc is killed.
            fd.write("  # Propagate kill if shell receives SIGTERM or SIGINT\n")
            fd.write("  trap 'kill -TERM $PID' TERM INT\n")
            fd.write("  "+run_stmt+" &\n")
            fd.write("  PID=$!\n")
            fd.write("  wait $PID\n")
            fd.write("  trap - TERM INT\n")
            fd.write("  wait $PID\n")
            fd.write("  EXIT_STATUS=$?\n")
            fd.write("fi\n\n")

        if retcode_path is not None:
            fd.write("echo $EXIT_STATUS > {retcode_path}\n".format(**locals()))

def local_exec_script(name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name):
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

    #log.info("Starting task in %s", job_dir)
    log.debug("executing: %s", bash_cmd)

    # create child in new process group so ctrl-c doesn't kill child process
    proc = subprocess.Popen(['bash', '-c', bash_cmd], close_fds=close_fds, preexec_fn=os.setsid)

    with open(os.path.join(job_dir, "description.txt"), "w") as fd:
        fd.write(desc_name)

    return Execution(name, id, job_dir, proc, outputs, captured_stdouts, desc_name)


def fetch_urls(obj, resolver):
    assert isinstance(obj, dict)
    new_obj = {}
    for k,v in obj.items():
        if isinstance(v, dict) and "$file_url" in v:
            url = v["$file_url"]
            filename = resolver.resolve(url)['filename']
            new_obj[k] = filename
        else:
            new_obj[k] = v
    return new_obj


def needs_resolution(obj):
    if not ("$xref_url" in obj):
        return False
    # Just noticed this.  weird, isn't it?  I think this should _probably_ be removed.
    for v in obj.values():
        if isinstance(v, dict) and "$value" in v:
            return False
    return True

def flatten_value(v):
    if isinstance(v, dict) and len(v) == 1 and "$value" in v:
        v = v["$value"]
    elif isinstance(v, dict) and len(v) == 1 and "$filename" in v:
        v = os.path.abspath(v["$filename"])
    return v

def flatten_parameters(d):
    "make dictionary into simple (string, string) pairs by handling $value and $filename special cases"
    pairs = []
    for k, v in d.items():
        v = flatten_value(v)
        pairs.append( (k,v) )
    return dict(pairs)

def preprocess_xref_inputs(j, resolver, inputs):
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

class NullResolveState:
    def add_script(self, script):
        pass

class PidProcStub:
    def __init__(self, pid):
        self.pid = pid

    def poll(self):
        try:
            os.kill(self.pid, 0)
            return None
        except OSError:
            return 0

# class ReportSuccessProcStub:
#     def __init__(self):
#         self.pid = 10000000
#
#     def poll(self):
#         return 0


class LocalExecClient:
    def __init__(self, resources):
        self.resources = resources

    def reattach(self, external_ref):
        d = json.loads(external_ref)
        return Execution(d['transform'], d['id'], d['job_dir'], PidProcStub(d['pid']), d['outputs'], d['captured_stdouts'], d['desc_name'])

    def preprocess_inputs(self, resolver, inputs):
        def resolve(obj_):
            assert isinstance(obj_, dep.Obj)
            obj = obj_.props
            assert isinstance(obj, dict)
            obj = fetch_urls(obj, resolver)
            return flatten_parameters(obj)

        result = {}
        for bound_name, obj_or_list in inputs:
            if isinstance(obj_or_list, list) or isinstance(obj_or_list, tuple):
                list_ = obj_or_list
                result[bound_name] = [resolve(obj_) for obj_ in list_]
            else:
                obj_ = obj_or_list
                result[bound_name] = resolve(obj_)
        return result, NullResolveState()

    def exec_script(self, name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name, resolve_state, resources):
        return local_exec_script(name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name)

import collections
import time

SgeState = collections.namedtuple("SgeState", ["update_timestamp", "status", "refresh_id"])

SGE_STATUS_SUBMITTED = "submitted"
SGE_STATUS_PENDING = "pending"
SGE_STATUS_RUNNING = "running"
SGE_STATUS_COMPLETE = "complete"
SGE_STATUS_UNKNOWN = "unknown"

from cpdshelpers import SimpleSSH

import tempfile

def drop_prefix(prefix, value):
    assert value[:len(prefix)] == prefix, "prefix=%r, value=%r" % (prefix, value)
    return value[len(prefix):]

def push_to_cas_with_pullmap(remote, source_and_dest, url_and_dest):
    source_and_dest = [ (os.path.abspath(source), dest) for source, dest in source_and_dest]
    log.debug("push_to_cas_with_pullmap, filenames: %s", source_and_dest)
    name_mapping = helper.push_to_cas(remote, [source for source, dest in source_and_dest])

    mapping = [ dict(remote="{}/{}".format(remote.remote_url, name_mapping[source]), local=dest)
                for source, dest in source_and_dest ]

    mapping += [dict(remote=src_url, local=dest)
                for src_url, dest in url_and_dest ]

    log.warn("name_mapping: %s", name_mapping)
    log.warn("mapping: %s", mapping)
    for rec in mapping:
        if rec["local"].startswith("/"):
            rec['local'] = os.path.relpath(rec['local'], remote.local_dir)

    mapping_str = json.dumps(dict(mapping=mapping))
    log.debug("Mapping str: %s", mapping_str)
    fd = tempfile.NamedTemporaryFile(mode="wt")
    fd.write(mapping_str)
    fd.flush()
    map_name = list(helper.push_to_cas(remote, [fd.name]).values())[0]
    fd.close()

    return "{}/{}".format(remote.remote_url, map_name)

def process_inputs_for_remote_exec(inputs):
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

            new_obj = {}
            for k, v in obj.items():
                if type(v) == dict and "$filename" in v:
                    cur_name = v["$filename"]
                    # Need to do something to avoid collisions.  Store under working dir?  maybe temp/filename-v
                    new_name = "temp/{}.{}".format(os.path.basename(cur_name), next_file_index())
                    files_to_upload_and_download.append((cur_name, new_name))
                    v = new_name
                elif isinstance(v, dict) and "$file_url" in v:
                    cur_name = v["$file_url"]
                    new_name = "temp/{}.{}".format(os.path.basename(cur_name), next_file_index())
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

class DelegateExecClient:
    def __init__(self, resources, local_workdir, remote_url, cas_remote_url, helper_path, command_template, python_path, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
        self.resources = resources
        self.helper_path = helper_path
        self.local_workdir = local_workdir
        self.remote_url = remote_url
        self.command_template = command_template
        self.cas_remote_url = cas_remote_url
        self.AWS_ACCESS_KEY_ID = AWS_ACCESS_KEY_ID
        self.AWS_SECRET_ACCESS_KEY = AWS_SECRET_ACCESS_KEY
        self.python_path = python_path

    def reattach(self, external_ref):
        d = json.loads(external_ref)
        return Execution(d['transform'], d['id'], d['job_dir'], PidProcStub(d['pid']), d['outputs'], d['captured_stdouts'], d['desc_name'])

    def preprocess_inputs(self, resolver, inputs):
        files_to_download, files_to_upload_and_download, result = process_inputs_for_remote_exec(inputs)
        return result, SGEResolveState(files_to_upload_and_download, files_to_download)

    def exec_script(self, name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name, resolver_state, resources):
        mem_in_mb = resources.get("mem", 1000)
        assert job_dir[:len(self.local_workdir)] == self.local_workdir
        rel_job_dir = job_dir[len(self.local_workdir)+1:]

        remote_url = "{}/{}".format(self.remote_url, rel_job_dir)
        local_job_dir = "{}/{}".format(self.local_workdir, rel_job_dir)
        local_wrapper_path = os.path.join(local_job_dir, "wrapper.sh")

        source_and_dest = list(resolver_state.files_to_upload_and_download)
        source_and_dest.append( (local_wrapper_path, "wrapper.sh") )

        if outputs is not None:
            local_write_results_path = os.path.join(local_job_dir, 'write_results.py')
            source_and_dest += [ (local_write_results_path, "write_results.py") ]
            run_stmts += ["{} write_results.py".format(self.python_path)]
            with open(local_write_results_path, "wt") as fd:
                fd.write("import json\n"
                         "results = {}\n"
                         "fd = open('results.json', 'wt')\n"
                         "fd.write(json.dumps(results))\n"
                         "fd.close()\n".format(repr(dict(outputs=outputs))))

        write_wrapper_script(local_wrapper_path, None, prologue, run_stmts, None)

        remote = helper.Remote(remote_url, local_job_dir, self.AWS_ACCESS_KEY_ID, self.AWS_SECRET_ACCESS_KEY)
        cas_remote = helper.Remote(self.cas_remote_url, local_job_dir, self.AWS_ACCESS_KEY_ID, self.AWS_SECRET_ACCESS_KEY)
        for _, dest in source_and_dest:
            assert dest[0] != '/'

        pull_map = push_to_cas_with_pullmap(cas_remote, source_and_dest, resolver_state.files_to_download)

        command = "{helper_path} exec --uploadresults " \
                        "-u retcode.json " \
                        "-u stdout.txt " \
                        "-u stderr.txt " \
                        "-o stdout.txt " \
                        "-e stderr.txt " \
                        "-r retcode.json " \
                        "-f {pull_map} " \
                        "--stage {stage_dir} " \
                        "{remote_url} . " \
                        "bash wrapper.sh\n".format(helper_path=self.helper_path,
                                                     remote_url = remote_url,
                                                     pull_map = pull_map,
                                                     stage_dir=".")

        #### start of local execution of delegate
        stdout_path = os.path.abspath(os.path.join(job_dir, "stdout.txt"))
        stderr_path = os.path.abspath(os.path.join(job_dir, "stderr.txt"))

        full_command = self.command_template.format(COMMAND=command, JOB=rel_job_dir)
        if capture_output:
            bash_cmd = "exec {full_command} {command} > {stdout_path} 2> {stderr_path}".format(**locals())
            captured_stdouts = (stdout_path, stderr_path)
            close_fds = True
        else:
            bash_cmd = "exec {full_command} {command}".format(**locals())
            captured_stdouts = None
            close_fds = False

        log.debug("executing: %s", bash_cmd)

        # create child in new process group so ctrl-c doesn't kill child process
        proc = subprocess.Popen(['bash', '-c', bash_cmd], close_fds=close_fds, preexec_fn=os.setsid, cwd=job_dir)

        with open(os.path.join(job_dir, "description.txt"), "w") as fd:
            fd.write(desc_name)

        def file_fetcher(name, destination):
            remote.download(name, destination, ignoreMissing=True, skipExisting=False)

        return DelegateExecution(name, id, job_dir, proc, outputs, captured_stdouts, desc_name, remote, file_fetcher)

class SgeExecClient:
    def __init__(self, host, sge_prologue, local_workdir, remote_workdir, remote_url, cas_remote_url, helper_path,
                 sge_cmd_prologue, resources, stage_dir, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY):
        assert "{{" not in cas_remote_url
        self.ssh_host = host
        self.sge_prologue = sge_prologue
        self.remote_workdir = remote_workdir
        self.remote_url = remote_url
        self.cas_remote_url = cas_remote_url
        self.local_workdir = local_workdir
        self.helper_path = helper_path
        self.resources = resources
        self.AWS_ACCESS_KEY_ID = AWS_ACCESS_KEY_ID
        self.AWS_SECRET_ACCESS_KEY = AWS_SECRET_ACCESS_KEY

        self.ssh = SimpleSSH()

        self.status_cache_expiry = 5
        self.job_completion_delay = 6
        self.last_status_refresh = None
        self.last_refresh_id = 1
        self.sge_cmd_prologue = sge_cmd_prologue

        # map of sge_job_id to sge status
        self.last_status = {}

        self.stage_dir = stage_dir

    def reattach(self, external_ref):
        d = json.loads(external_ref)
        remote_job_dir = d['remote_job_dir']
        remote = helper.Remote(d['remote_url'], d['local_job_dir'], self.AWS_ACCESS_KEY_ID, self.AWS_SECRET_ACCESS_KEY)
        sge_job_id = d['sge_job_id']
        self._saw_job_id(sge_job_id, SGE_STATUS_SUBMITTED)
        return SGEExecution(d['name'], d['id'], d['job_dir'], sge_job_id, d['desc_name'], self, remote, d, self._mk_file_fetcher(remote_job_dir))

    def _saw_job_id(self, sge_job_id, status):
        self.last_status[sge_job_id] = SgeState(time.time(), status, self.last_refresh_id)

    def _refresh_job_statuses(self):
        qstat_command = "qstat -xml"
        if self.sge_cmd_prologue is not None:
            qstat_command = self.sge_cmd_prologue +" ; " + qstat_command

        stdout = self.ssh.exec_cmd(self.ssh_host, qstat_command, logger=log.debug)

        self.last_refresh_id += 1

        doc = ETree.fromstring(stdout)
        job_list = doc.findall(".//job_list")

        for job in job_list:
            job_id = job.find("JB_job_number").text

            state = job.attrib['state']
            if state == "running":
                self._saw_job_id(job_id, SGE_STATUS_RUNNING)
            elif state == "pending":
                self._saw_job_id(job_id, SGE_STATUS_PENDING)
            else:
                self._saw_job_id(job_id, SGE_STATUS_UNKNOWN)

    def get_status(self, sge_job_id):
        now = time.time()
        if self.last_status_refresh is None or (now - self.last_status_refresh) > self.status_cache_expiry:
            self._refresh_job_statuses()
            self.last_status_refresh = now

        status_obj = self.last_status[sge_job_id]
        if status_obj.refresh_id != self.last_refresh_id:
            # this job was missing the last time we refreshed
            if now - status_obj.update_timestamp > self.job_completion_delay:
                return SGE_STATUS_COMPLETE

        return status_obj.status

    def preprocess_inputs(self, resolver, inputs):
        files_to_download, files_to_upload_and_download, result = process_inputs_for_remote_exec(inputs)
        return result, SGEResolveState(files_to_upload_and_download, files_to_download)

    def add_script(self, resolver_state, filename):
        #assert not filename[0] == "/"
        resolver_state.files_to_upload_and_download.append((filename, os.path.basename(filename)))

    def _exec_qsub(self, stdout, stderr, script_path, mem_in_mb, name):
        qsub_command = "qsub -N {name} -l h_vmem={mem_in_mb}M -terse -o {stdout} -e {stderr} {script_path}".format(name=name, stdout=stdout, stderr=stderr, script_path=script_path, mem_in_mb=mem_in_mb)

        if self.sge_cmd_prologue is not None:
            qsub_command = self.sge_cmd_prologue +" ; " + qsub_command

        sge_job_id = self.ssh.exec_cmd(self.ssh_host, qsub_command).strip()
        assert re.match("\\d+", sge_job_id) is not None
        self._saw_job_id(sge_job_id, SGE_STATUS_SUBMITTED)

        return sge_job_id

    def exec_generic_command(self, rel_job_dir, command, mem_in_mb, name):
        remote_job_dir = "{}/{}".format(self.remote_workdir, rel_job_dir)

        docker_launch_script = "{}/run.sh".format(remote_job_dir)
        script = "#!/bin/bash\n{}\n".format(" ".join(command))
        self.ssh.put_string(self.ssh_host, script, docker_launch_script)

        self._exec_qsub(remote_job_dir+"/stdout.txt", remote_job_dir+"/stderr.txt", docker_launch_script, mem_in_mb, name)

    def exec_script(self, name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name, resolver_state, resources):
        mem_in_mb = resources.get("mem", 1000)
        assert job_dir[:len(self.local_workdir)] == self.local_workdir
        rel_job_dir = job_dir[len(self.local_workdir)+1:]

        remote_url = "{}/{}".format(self.remote_url, rel_job_dir)
        remote_job_dir = "{}/{}".format(self.remote_workdir, rel_job_dir)
        local_job_dir = "{}/{}".format(self.local_workdir, rel_job_dir)
        local_wrapper_path = os.path.join(local_job_dir, "wrapper.sh")
        remote_wrapper_path = os.path.join(remote_job_dir, "wrapper.sh")

        source_and_dest = list(resolver_state.files_to_upload_and_download)

        if outputs is not None:
            local_write_results_path = os.path.join(local_job_dir, 'write_results.py')
            source_and_dest += [ (local_write_results_path, "write_results.py") ]
            run_stmts += ["python write_results.py"]
            with open(local_write_results_path, "wt") as fd:
                fd.write("import json\n"
                         "results = {}\n"
                         "fd = open('results.json', 'wt')\n"
                         "fd.write(json.dumps(results))\n"
                         "fd.close()\n".format(repr(dict(outputs=outputs))))

        remote = helper.Remote(remote_url, local_job_dir, self.AWS_ACCESS_KEY_ID, self.AWS_SECRET_ACCESS_KEY)
        cas_remote = helper.Remote(self.cas_remote_url, local_job_dir, self.AWS_ACCESS_KEY_ID, self.AWS_SECRET_ACCESS_KEY)
        for _, dest in source_and_dest:
            assert dest[0] != '/'
        pull_map = push_to_cas_with_pullmap(cas_remote, source_and_dest, resolver_state.files_to_download)

        self.ssh.exec_cmd(self.ssh_host, "mkdir -p {}".format(remote_job_dir))
        helper_script = "cd {remote_job_dir}\n" \
                        "{helper_path} exec --uploadresults " \
                        "-u retcode.json " \
                        "-u stdout.txt " \
                        "-u stderr.txt " \
                        "-o stdout.txt " \
                        "-e stderr.txt " \
                        "-r retcode.json " \
                        "-f {pull_map} " \
                        "--stage {stage_dir} " \
                        "{remote_url} . " \
                        "bash wrapper.sh\n".format(helper_path=self.helper_path,
                                                     remote_url = remote_url,
                                                     remote_job_dir = remote_job_dir,
                                                     pull_map = pull_map,
                                                     stage_dir=self.stage_dir)

        if self.sge_prologue is not None:
            helper_script = self.sge_prologue + "\n" + helper_script

        pull_and_run_script = "{}/pull_and_run.sh".format(remote_job_dir)
        self.ssh.put_string(self.ssh_host, helper_script, pull_and_run_script)

        write_wrapper_script(local_wrapper_path, remote_job_dir, prologue, run_stmts, None)

        log.debug("put %s %s", local_wrapper_path, remote_wrapper_path)
        self.ssh.put(self.ssh_host, local_wrapper_path, remote_wrapper_path)

        sge_job_id = self._exec_qsub(remote_job_dir+"/helper_stdout.txt", remote_job_dir+"/helper_stderr.txt", pull_and_run_script, mem_in_mb, rel_job_dir)

        extern_ref = dict(remote_url=remote_url,
                          local_job_dir=local_job_dir,
                          name=name,
                          id=id, job_dir=rel_job_dir,
                          sge_job_id=sge_job_id,
                          desc_name=desc_name,
                          remote_job_dir=remote_job_dir)

        return SGEExecution(name, id, job_dir, sge_job_id, desc_name, self, remote, extern_ref, self._mk_file_fetcher(remote_job_dir))

    def _mk_file_fetcher(self, dir):
        def fetch(filename, destination):
            path = os.path.join(dir, filename)
            try:
                self.ssh.get(self.ssh_host, path, destination)
                return "{}:{}".format(self.ssh_host, path)
            except FileNotFoundError:
                log.warning("No file at {}:{}".format(self.ssh_host, path))
        return fetch

    def cancel(self, sge_job_id):
        qdel_command = "qdel {}".format(sge_job_id)
        if self.sge_cmd_prologue is not None:
            qdel_command = self.sge_cmd_prologue +" ; " + qdel_command

        # qdel may fail if job terminates while waiting for input, so just hope for the best
        # if we got an error
        self.ssh.exec_cmd(self.ssh_host, qdel_command, assert_success=False)

class SGEResolveState:
    def __init__(self, files_to_upload_and_download, files_to_download):
        self.files_to_upload_and_download = files_to_upload_and_download
        self.files_to_download = files_to_download

    def add_script(self, filename):
        self.files_to_upload_and_download.append( (filename, os.path.basename(filename)) )

def _resolve_filenames(remote, artifact):
    new_artifact = dict()
    for k, v in artifact.items():
        if type(v) == dict and "$filename" in v:
            v = {"$file_url": remote.remote_url+"/"+v["$filename"]}
        new_artifact[k] = v

    log.debug("translated %r -> %r", artifact, new_artifact)

    return new_artifact

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


class SGEExecution:
    def __init__(self, transform, id, job_dir, sge_job_id, desc_name, client, remote, extern_ref, file_fetch):
        self.transform = transform
        self.id = id
        self.job_dir = job_dir
        self.sge_job_id = sge_job_id
        self.desc_name = desc_name
        self.client = client
        self.remote = remote
        self.extern_ref = extern_ref
        self.file_fetch = file_fetch

    def cancel(self):
        log.warn("Executing qdel to delete job %s (%s)", self.sge_job_id, self.desc_name)
        self.client.cancel(self.sge_job_id)

    def get_state_label(self):
        return "SGE-"+self.client.get_status(self.sge_job_id)

    def get_external_id(self):
        return json.dumps(self.extern_ref)

    def _log_failure(self, msg):
        _log_remote_failure(self.file_fetch, msg)

    def get_completion(self):
        failure, outputs = self._get_completion()
        if failure is not None:
            log.error("SGE Job {} running {} failed".format(self.sge_job_id, self.desc_name))
            self._log_failure(failure)
        return failure, outputs

    def _get_completion(self):
        status = self.client.get_status(self.sge_job_id)

        if status != SGE_STATUS_COMPLETE:
            return None, None

        log.debug("About to download retcode.json")

        retcode_content = self.remote.download_as_str("retcode.json")
        if retcode_content is not None:
            retcode = json.loads(retcode_content)['retcode']
        else:
            log.debug("got no retcode")
            retcode = None

        if retcode != 0:
            return("shell command failed with {}".format(repr(retcode)), None)

        results_str = self.remote.download_as_str("results.json")
        if results_str is None:
            return("script reported success but results.json is missing!", None)

        results = json.loads(results_str)

        log.info("Rule {} completed ({}). Results: {}".format(self.desc_name, self.job_dir, results))
        assert type(results['outputs']) == list
        outputs = [_resolve_filenames(self.remote, o) for o in results['outputs']]

        return None, outputs

def assert_has_only_props(properties, names):
    assert set(properties.keys()) == set(names), "Expected properties: {}, but got {}".format(names, properties.keys())


def create_client(name, config, properties):
    resources = {"slots": 1}
    for k, v in properties.get("resources", {}).items():
        resources[k] = float(v)
    type = properties.get('type')
    if type == 'sge':
        resources['mem'] = 1e20
        expected_props = ["type", "SGE_HOST", "SGE_PROLOGUE", "SGE_REMOTE_WORKDIR", "SGE_HELPER_PATH", "SGE_CMD_PROLOGUE", "resources"]
        assert_has_only_props(properties, expected_props)
        return SgeExecClient(properties["SGE_HOST"],
                             properties["SGE_PROLOGUE"],
                             config["WORKING_DIR"],
                             properties["SGE_REMOTE_WORKDIR"]+"/"+config["EXECUTION_ID"],
                             config["S3_STAGING_URL"]+"/"+config["EXECUTION_ID"],
                             config["S3_STAGING_URL"],
                             properties["SGE_HELPER_PATH"],
                             properties["SGE_CMD_PROLOGUE"],
                             resources,
                             properties["SGE_REMOTE_WORKDIR"] + "/CAS",
                             config["AWS_ACCESS_KEY_ID"],
                             config["AWS_SECRET_ACCESS_KEY"]
                             )
    elif type == "local":
        assert_has_only_props(properties, ["type", "resources"])
        return LocalExecClient(resources)
    elif type == "delegate":
        assert_has_only_props(properties, ["type", "resources", "HELPER_PATH", "COMMAND_TEMPLATE"])
        return DelegateExecClient(resources, config["WORKING_DIR"], config["S3_STAGING_URL"]+"/"+config["EXECUTION_ID"], config["S3_STAGING_URL"],
                                  properties["HELPER_PATH"], properties["COMMAND_TEMPLATE"], config.get("PYTHON_PATH", "python"), config["AWS_ACCESS_KEY_ID"],
                             config["AWS_SECRET_ACCESS_KEY"])
    else:
        raise Exception("Unrecognized exec-profile 'type': {}".format(type))

