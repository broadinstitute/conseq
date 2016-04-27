import os
import logging
import subprocess
from conseq import dep
import json
import datetime

log = logging.getLogger(__name__)

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

    @property
    def results_path(self):
        return os.path.join(self.job_dir, "results.json")

    def get_completion(self):
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

    def localize(self, j, resolver, inputs):
        return preprocess_inputs(j, resolver, inputs)

    def exec_script(self, name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name):
        return exec_script(name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name)

# class SgeExecClient:
#     def __init__(self, remote_workdir, s3_workdir):
#         self.remote_workdir = remote_workdir
#         self.s3_workdir = s3_workdir
#
#     def reattach(self, external_ref):
#         raise Exception("unimp")
#
#     def localize(self, inputs):
#         raise Exception("unimp")
#
#     def exec_script(self, name, id, job_dir, run_stmts, outputs, capture_output, prologue, desc_name):
#         raise Exception("unimp")
#         wrapper_path = ""
#         job_dir = "{}/{}".format(self.remote_workdir, self.job_dir)
#         run_stmts = [download_command] + run_stmts + [upload_command]
#         write_wrapper_script(wrapper_path, job_dir, prologue, run_stmts, "retcode.txt")
#
#         # scp wrapper_path remote_wrapper_path
#         # copy all files from job_dir to remote?
#
#         qsub_id = subprocess.check_output(['qsub', remote_wrapper_path])
#
#         return Execution(name, id, job_dir, proc, outputs, captured_stdouts, desc_name)
