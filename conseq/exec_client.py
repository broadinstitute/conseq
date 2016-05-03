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

def log_job_output(job_dir, captured_stdouts, line_count=20):
    stdout_path, stderr_path = captured_stdouts
    log.error("Dumping last {} lines of {}".format(line_count, stdout_path))
    _tail_file(stdout_path)
    log.error("Dumping last {} lines of {}".format(line_count, stderr_path))
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

    def get_external_id(self):
        return "PID:{}".format(self.proc.pid)

    @property
    def results_path(self):
        return os.path.join(self.job_dir, "results.json")

    def _log_failure(self, failure):
        log.error("Task failed %s: %s", self.desc_name, failure)
        if self.captured_stdouts != None:
            log_job_output(self.job_dir, self.captured_stdouts)

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
    else:
        bash_cmd = "exec bash {wrapper_path}".format(**locals())
        captured_stdouts = None

    log.info("Starting task in %s", job_dir)
    log.debug("executing: %s", bash_cmd)
    proc = subprocess.Popen(['bash', '-c', bash_cmd])

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

def preprocess_inputs(j, resolver, inputs):
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
            obj = obj_copy

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
    return result, xrefs_resolved[0]

class LocalExecClient:
    def reattach(self, external_ref):
        raise Exception("unimp")
        # stdout_path = os.path.join(e.job_dir, "stdout.txt")
        # stderr_path = os.path.join(e.job_dir, "stderr.txt")
        # with open(os.path.join(e.job_dir, "description.txt")) as fd:
        #     desc_name = fd.read()
        # ee = Execution(e.transform, e.id, e.job_dir, PidProcStub(e.exec_xref), rule.outputs, (stdout_path, stderr_path), desc_name)

    def preprocess_inputs(self, j, resolver, inputs):
        return preprocess_inputs(j, resolver, inputs)

    def exec_script(self, name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name):
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

class SgeExecClient:
    def __init__(self, host, sge_prologue, local_workdir, remote_workdir, remote_url, helper_path):
        self.ssh_host = host
        self.sge_prologue = sge_prologue
        self.remote_workdir = remote_workdir
        self.remote_url = remote_url
        self.local_workdir = local_workdir
        self.helper_path = helper_path

        self.ssh = SimpleSSH()

        self.status_cache_expiry = 30
        self.job_completion_delay = 10
        self.last_status_refresh = None
        self.last_refresh_id = 1
        self.sge_remote_proc_prologue = "source /broad/software/scripts/useuse\n" \
                        "use -q Python-2.7\n"
        self.sge_cmd_prologue = "use -q UGER"

        # map of sge_job_id to sge status
        self.last_status = {}

    def reattach(self, external_ref):
        d = json.loads(external_ref)
        remote = helper.Remote(d['remote_url'], d['local_job_dir'])
        return SGEExecution(d['name'], d['id'], d['job_dir'], d['sge_job_id'], d['desc_name'], self, remote, d)


    def _saw_job_id(self, sge_job_id, status):
        self.last_status[sge_job_id] = SgeState(time.time(), status, self.last_refresh_id)

    def _refresh_job_statuses(self):
        qstat_command = "qstat -xml"
        if self.sge_cmd_prologue is not None:
            qstat_command = self.sge_cmd_prologue +" ; " + qstat_command

        stdout = self.ssh.exec_cmd(self.ssh_host, qstat_command)

        #print("stdout: %s" % repr(stdout))

        #handle = subprocess.Popen(["qstat", "-xml"], stdout=subprocess.PIPE)
        #stdout, stderr = handle.communicate()

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

        status_obj = self.last_status[sge_job_id]
        if status_obj.refresh_id != self.last_refresh_id:
            # this job was missing the last time we refreshed
            if now - status_obj.update_timestamp > self.job_completion_delay:
                return SGE_STATUS_COMPLETE

        return status_obj.status

    def exec_script(self, name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name):
        remote_url = "{}/{}".format(self.remote_url, job_dir)
        remote_job_dir = "{}/{}".format(self.remote_workdir, job_dir)
        local_job_dir = "{}/{}".format(self.local_workdir, job_dir)
        local_wrapper_path = os.path.join(local_job_dir, "wrapper.sh")
        remote_wrapper_path = os.path.join(remote_job_dir, "wrapper.sh")

        filenames = ["script1"]

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
        pull_map = helper.push_to_cas_with_pullmap(remote, filenames)

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

        write_wrapper_script(local_wrapper_path, remote_job_dir, prologue, run_stmts, "retcode.txt")

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
                          id=id, job_dir=job_dir,
                          sge_job_id=sge_job_id,
                          desc_name=desc_name)

        return SGEExecution(name, id, job_dir, sge_job_id, desc_name, self, remote, extern_ref)


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

    def get_external_id(self):
        return json.dumps(self.extern_ref)

    def _log_failure(self, msg):
        log.error(msg)
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

        print("retcode=", repr(retcode))
        if retcode != "0":
            print("WTF", repr(retcode))
            return("shell command failed with {}".format(repr(retcode)), None)
        print("okay, everything is fine")

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

