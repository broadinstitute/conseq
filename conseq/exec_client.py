import os
import logging
import subprocess
from conseq import dep
import json
import datetime
import xml.etree.ElementTree as ETree
import re

from conseq import helper

log = logging.getLogger(__name__)

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

def log_job_output(stdout_path, stderr_path, line_count=20):
    log.error("Dumping last {} lines of stdout ({})".format(line_count, stdout_path))
    _tail_file(stdout_path)
    log.error("Dumping last {} lines of stderr ({})".format(line_count, stderr_path))
    _tail_file(stderr_path)

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

def write_wrapper_script(wrapper_path, job_dir, prologue, run_stmts, retcode_path):
    with open(wrapper_path, "wt") as fd:
        fd.write("set -ex\n")
        fd.write("cd {job_dir}\n".format(**locals()))

        fd.write(prologue+"\n")

        for command in run_stmts:
            fd.write(command)
            fd.write(" &&\\\n")

        fd.write("true\n")
        if retcode_path is not None:
            fd.write("echo $? > {retcode_path}\n".format(**locals()))

def exec_script(name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name):
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

    log.info("Starting task in %s", job_dir)
    log.debug("executing: %s", bash_cmd)

    # create child in new process group so ctrl-c doesn't kill child process
    proc = subprocess.Popen(['bash', '-c', bash_cmd], close_fds=close_fds, preexec_fn=os.setsid)

    with open(os.path.join(job_dir, "description.txt"), "w") as fd:
        fd.write(desc_name)

    return Execution(name, id, job_dir, proc, outputs, captured_stdouts, desc_name)

def needs_url_fetch(obj):
    for v in obj.values():
        if isinstance(v, dict) and "$file_url" in v:
            return True
    return False

def needs_resolution(obj):
    if not ("$xref_url" in obj):
        return False
    for v in obj.values():
        if isinstance(v, dict) and "$value" in v:
            return False
    return True

def fetch_urls(obj, resolver):
    new_obj = {}
    for k,v in obj.items():
        if isinstance(v, dict) and "$file_url" in v:
            url = v["$file_url"]
            filename = resolver.resolve(url)['filename']
            new_obj[k] = {"$filename": filename}
        else:
            new_obj[k] = v
    return new_obj

def flatten_parameters(d):
    pairs = []
    for k, v in d.items():
        if isinstance(v, dict) and len(v) == 1 and "$value" in v:
            v = v["$value"]
        elif isinstance(v, dict) and len(v) == 1 and "$filename" in v:
            v = os.path.abspath(v["$filename"])
        pairs.append( (k,v) )
    return dict(pairs)

def preprocess_xref_inputs(j, resolver, inputs):
    xrefs_resolved = [False]

    def resolve(obj_):
        assert isinstance(obj_, dep.Obj)
        obj = obj_.props
        obj_copy = None
        if needs_url_fetch(obj):
            obj_copy = fetch_urls(obj, resolver)

        elif needs_resolution(obj):
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
    def reattach(self, external_ref):
        d = json.loads(external_ref)
        return Execution(d['transform'], d['id'], d['job_dir'], PidProcStub(d['pid']), d['outputs'], d['captured_stdouts'], d['desc_name'])

    def preprocess_inputs(self, resolver, inputs):
        def resolve(obj_):
            assert isinstance(obj_, dep.Obj)
            obj = obj_.props
            assert isinstance(obj, dict)
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

    def exec_script(self, name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name, resolve_state):
        return exec_script(name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name)

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

def push_to_cas_with_pullmap(remote, filenames):
    name_mapping = helper.push_to_cas(remote, filenames)

    mapping = [ dict(remote="{}/{}".format(remote.remote_url, v), local=k) for k, v in name_mapping.items() ]

    print(name_mapping)
    for rec in mapping:
        if rec["local"].startswith("/"):
            rec['local'] = drop_prefix(os.path.abspath(remote.local_dir)+"/", rec['local'])

    mapping_str = json.dumps(dict(mapping=mapping))
    print("Mapping str: ", mapping_str)
    fd = tempfile.NamedTemporaryFile(mode="wt")
    fd.write(mapping_str)
    fd.flush()
    map_name = list(helper.push_to_cas(remote, [fd.name]).values())[0]
    fd.close()

    return "{}/{}".format(remote.remote_url, map_name)


class SgeExecClient:
    def __init__(self, host, sge_prologue, local_workdir, remote_workdir, remote_url, helper_path):
        self.ssh_host = host
        self.sge_prologue = sge_prologue
        self.remote_workdir = remote_workdir
        self.remote_url = remote_url
        self.local_workdir = local_workdir
        self.helper_path = helper_path

        self.ssh = SimpleSSH()

        self.status_cache_expiry = 5
        self.job_completion_delay = 6
        self.last_status_refresh = None
        self.last_refresh_id = 1
        self.sge_remote_proc_prologue = "source /broad/software/scripts/useuse\n" \
                        "use -q Python-2.7 R-3.2\n"
        self.sge_cmd_prologue = "use -q UGER"

        # map of sge_job_id to sge status
        self.last_status = {}

    def reattach(self, external_ref):
        d = json.loads(external_ref)
        remote = helper.Remote(d['remote_url'], d['local_job_dir'])
        sge_job_id = d['sge_job_id']
        self._saw_job_id(sge_job_id, SGE_STATUS_SUBMITTED)
        return SGEExecution(d['name'], d['id'], d['job_dir'], sge_job_id, d['desc_name'], self, remote, d)

    def _saw_job_id(self, sge_job_id, status):
        self.last_status[sge_job_id] = SgeState(time.time(), status, self.last_refresh_id)

    def _refresh_job_statuses(self):
        qstat_command = "qstat -xml"
        if self.sge_cmd_prologue is not None:
            qstat_command = self.sge_cmd_prologue +" ; " + qstat_command

        stdout = self.ssh.exec_cmd(self.ssh_host, qstat_command)

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
        files_to_upload_and_download = []
        files_to_download = []

        def next_file_index():
            return len(files_to_upload_and_download) + len(files_to_download)

        #need to find all files that will be downloaded and update with $filename of what eventual local location will be.
        def resolve(obj):
            new_obj = {}
            for k, v in obj.items():
                if type(v) == dict and "$filename" in v:
                    cur_name = v["$filename"]
                    #Need to do something to avoid collisions.  Store under working dir?  maybe temp/filename-v
                    new_name = "temp/{}.{}".format(os.path.basename(cur_name), next_file_index())
                    files_to_upload_and_download.append((cur_name, new_name))
                    v = {"$filename": new_name}
                elif isinstance(v, dict) and "$file_url" in v:
                    cur_name = v["$file_url"]
                    new_name = "temp/{}.{}".format(os.path.basename(cur_name), next_file_index())
                    files_to_download.append((cur_name, new_name))
                    v = {"$filename": new_name}
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

        return result, SGEResolveState(files_to_upload_and_download, files_to_download)

    def add_script(self, resolver_state, filename):
        resolver_state.files_to_upload_and_download.append((filename, filename))

    def exec_script(self, name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name, resolver_state):
        assert job_dir[:len(self.local_workdir)] == self.local_workdir
        rel_job_dir = job_dir[len(self.local_workdir)+1:]

        remote_url = "{}/{}".format(self.remote_url, rel_job_dir)
        remote_job_dir = "{}/{}".format(self.remote_workdir, rel_job_dir)
        local_job_dir = "{}/{}".format(self.local_workdir, rel_job_dir)
        local_wrapper_path = os.path.join(local_job_dir, "wrapper.sh")
        remote_wrapper_path = os.path.join(remote_job_dir, "wrapper.sh")

        filenames = [x[0] for x in resolver_state.files_to_upload_and_download]

        if outputs is not None:
            filenames += ["write_results.py"]
            run_stmts += ["python write_results.py"]
            with open("{}/write_results.py".format(local_job_dir), "wt") as fd:
                fd.write("import json\n"
                         "results = {}\n"
                         "fd = open('results.json', 'wt')\n"
                         "fd.write(json.dumps(results))\n"
                         "fd.close()\n".format(repr(dict(outputs=outputs))))

        remote = helper.Remote(remote_url, local_job_dir)
        pull_map = push_to_cas_with_pullmap(remote, filenames)

        self.ssh.exec_cmd(self.ssh_host, "mkdir -p {}".format(remote_job_dir))
        helper_script = "cd {remote_job_dir}\n" \
                        "{helper_path} exec " \
                        "-u . -o stdout.txt -e stderr.txt -r retcode.txt -f {pull_map} " \
                        "{remote_url} . " \
                        "bash wrapper.sh\n".format(helper_path=self.helper_path,
                                                 remote_url = remote_url,
                                                 remote_job_dir = remote_job_dir,
                                                 pull_map = pull_map)

        if self.sge_remote_proc_prologue is not None:
            helper_script = self.sge_remote_proc_prologue + "\n" + helper_script

        pull_and_run_script = "{}/pull_and_run.sh".format(remote_job_dir)
        self.ssh.put_string(self.ssh_host, helper_script, pull_and_run_script)

        write_wrapper_script(local_wrapper_path, remote_job_dir, prologue, run_stmts, None)

        print("put", local_wrapper_path, remote_wrapper_path)
        self.ssh.put(self.ssh_host, local_wrapper_path, remote_wrapper_path)

        qsub_command = "qsub -terse -o {remote_job_dir}/helper_stdout.txt -e {remote_job_dir}/helper_stderr.txt {pull_and_run_script}".format(
            remote_job_dir=remote_job_dir, pull_and_run_script=pull_and_run_script)

        if self.sge_cmd_prologue is not None:
            qsub_command = self.sge_cmd_prologue +" ; " + qsub_command

        sge_job_id = self.ssh.exec_cmd(self.ssh_host, qsub_command).strip()
        assert re.match("\\d+", sge_job_id) is not None
        self._saw_job_id(sge_job_id, SGE_STATUS_SUBMITTED)

        extern_ref = dict(remote_url=remote_url, local_job_dir=local_job_dir, name=name,
                          id=id, job_dir=rel_job_dir,
                          sge_job_id=sge_job_id,
                          desc_name=desc_name)

        return SGEExecution(name, id, job_dir, sge_job_id, desc_name, self, remote, extern_ref)

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
        self.files_to_upload_and_download.append( (filename, filename) )

class SGEExecution:
    def __init__(self, name, id, job_dir, sge_job_id, desc_name, client, remote, extern_ref):
        self.name = name
        self.id = id
        self.job_dir = job_dir
        self.sge_job_id = sge_job_id
        self.desc_name = desc_name
        self.client = client
        self.remote = remote
        self.extern_ref = extern_ref

    def cancel(self):
        log.warn("Executing qdel to delete job %s (%s)", self.sge_job_id, self.desc_name)
        self.client.cancel(self.sge_job_id)

    def get_state_label(self):
        return "SGE-"+self.client.get_status(self.sge_job_id)

    def get_external_id(self):
        return json.dumps(self.extern_ref)

    def _log_failure(self, msg):
        log.error(msg)

        with tempfile.NamedTemporaryFile() as tmpstderr:
            with tempfile.NamedTemporaryFile() as tmpstdout:
                log.info("Fetching error and output logs for failed job")
                self.remote.download("stderr.txt", tmpstderr.name, ignoreMissing=True)
                self.remote.download("stdout.txt", tmpstdout.name, ignoreMissing=True)
                log_job_output(tmpstdout.name, tmpstderr.name)

        # TODO: Add dumping of stderr,stdout

    def get_completion(self):
        failure, outputs = self._get_completion()
        if failure is not None:
            self._log_failure(failure)
        return failure, outputs

    def _resolve_filenames(self, artifact):
        new_artifact = dict()
        for k, v in artifact.items():
            if type(v) == dict and "$filename" in v:
                v = {"$file_url": self.remote.remote_url+"/"+v["$filename"]}
            new_artifact[k] = v

        print("translated %r -> %r"% (artifact, new_artifact))

        return new_artifact

    def _get_completion(self):
        status = self.client.get_status(self.sge_job_id)

        if status != SGE_STATUS_COMPLETE:
            return None, None

        retcode = self.remote.download_as_str("retcode.txt")

        # print("retcode=", repr(retcode))
        if retcode != "0":
            print("WTF", repr(retcode))
            return("shell command failed with {}".format(repr(retcode)), None)
        # print("okay, everything is fine")

        results_str = self.remote.download_as_str("results.json")
        if results_str is None:
            return("script reported success but results.json is missing!", None)

        results = json.loads(results_str)

        log.info("Rule {} completed ({}). Results: {}".format(self.desc_name, self.job_dir, results))
        assert type(results['outputs']) == list
        outputs = [self._resolve_filenames(o) for o in results['outputs']]

        # # print summary of output files with full paths
        # files_written = []
        # for output in outputs:
        #     for value in output.values():
        #         if isinstance(value, dict) and "$filename" in value:
        #             files_written.append(value["$filename"])
        #
        # if len(files_written):
        #     log.warn("Rule %s wrote the following files:\n%s", self.transform, "\n".join(["\t"+x for x in files_written]))

        return None, outputs

