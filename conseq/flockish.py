import os
import re
import subprocess
import json
from conseq.helper import Remote, drop_prefix, push_str_to_cas
import argparse
import logging
from conseq import parser
from conseq import exec_client
from conseq import helper

log = logging.getLogger(__name__)

class ScatterGather:
    def __init__(self, exec_fn):
        self.exec_fn = exec_fn

    def is_task_complete(self, remote, name):
        text = remote.download_as_str("completed/"+name)
        if text != None:
            state = json.loads(text)
            if state["state"] == "success":
                return True

        return False

    def check_state_complete(self, remote, state, max_jobs):
        if state == "scatter":
            assert self.is_task_complete(remote, "scatter")
        elif state == "map":
            indices = self.find_map_indices_not_run(remote, max_jobs)
            assert len(indices) == 0
        elif state == "gather":
            assert self.is_task_complete(remote, "gather")
        elif state != 'created':
            raise Exception("unknown state: {}".format(state))

    def do_scatter(self, scatter_fn, remote, rcode, args={}):
        if self.is_task_complete(remote, "scatter"):
            return

        return self.submit_scatter(scatter_fn, remote, rcode, args)

    def do_map(self, map_fn, remote, rcode, max_jobs):
        indices = self.find_map_indices_not_run(remote, max_jobs)
        if len(indices) == 0:
            return

        return self.submit_map(map_fn, indices, remote, rcode)

    def do_gather(self, gather_fn, remote, rcode):
        if self.is_task_complete(remote, "gather"):
            return

        return self.submit_gather(gather_fn, remote, rcode)


    def generate_r_script(self, rcode, rest):
        execute_fn_r = open(os.path.join(os.path.dirname(__file__), "execute-r-fn.R"), "rt").read()
        return "{}\n{}\n{}\n".format(rcode, execute_fn_r, rest)


    def find_map_indices_not_run(self, remote, max_jobs):
        indices = set()

        input_prefix = remote.remote_path+"/map-in"
        for key in remote.bucket.list(prefix=input_prefix):
            fn = drop_prefix(input_prefix+"/", key.key)
            m = re.match("(\\d+)", fn)
            if m != None:
                indices.add(m.group(1))

        if max_jobs is not None:
            # only take first few examples
            x=list(indices)
            x.sort()
            indices = set(x[:max_jobs])

        output_prefix = remote.remote_path+"/map-out"
        for key in remote.bucket.list(prefix=output_prefix):
            fn = drop_prefix(output_prefix+"/", key.key)
            m = re.match("(\\d+)", fn)
            if m != None and m.group(1) in indices:
                indices.remove(m.group(1))

        return indices

    def submit_config(self, url):
        command = ["docker",
                   "run",
                   "-e", 'AWS_ACCESS_KEY_ID='+ os.getenv('AWS_ACCESS_KEY_ID'),
                   "-e", 'AWS_SECRET_ACCESS_KEY=' + os.getenv('AWS_SECRET_ACCESS_KEY'),
                   "-w", "/work", "-i",
                   "enrichment", "python", "/helper.py", "exec-config", url]
        log.info("Running %s", " ".join(command))
        return self.exec_fn(command)

    def submit_scatter(self, scatter_fn, remote, rcode, args):
        args_url = push_str_to_cas(remote, json.dumps(args))
        r_script = self.generate_r_script(rcode, "phlock.exec.scatter(\"{}\")".format(scatter_fn))
        script_url = push_str_to_cas(remote, r_script)

        config = dict(
            remote_url = remote.remote_url,
             pull=[{"src": args_url, "dest": "scatter-in/params.json", "isDir": False},
                   {"src": script_url, "dest": "script.R", "isDir": False},],
             mkdir=["shared", "map-in", "results"],
             command=["Rscript", "script.R"],
             exec_summary="retcode.json",
             stdout="stdout.txt",
             stderr="stderr.txt",
             push=[{"src": "shared", "dest": "shared", "isDir": True},
                   {"src": "map-in", "dest": "map-in", "isDir": True},
                   {"src": "results", "dest": "results", "isDir": True},
                   {"src": "retcode.json", "dest": "completed/scatter", "isDir": False},
                   {"src": "stdout.txt", "dest": "logs/scatter/stdout.txt", "isDir": False},
                   {"src": "stderr.txt", "dest": "logs/scatter/stderr.txt", "isDir": False},])

        config_url = push_str_to_cas(remote, json.dumps(config))
        sge_job_id = self.submit_config(remote.remote_url+"/"+config_url)
        return [sge_job_id]

    def submit_map(self, map_fn, indices, remote, rcode):
        r_script = self.generate_r_script(rcode, "phlock.exec.map(\"{}\")".format(map_fn))
        script_url = push_str_to_cas(remote, r_script)
        sge_job_ids = []

        for index in indices:
            config = dict(
                remote_url = remote.remote_url,
                 pull=[{"src": "shared", "dest": "shared", "isDir": True},
                       {"src": "map-in/"+index, "dest": "map-in/"+index, "isDir": False},
                       {"src": script_url, "dest": "script.R", "isDir": False},],
                 mkdir=["map-out", "results"],
                 command=["Rscript", "script.R"],
                 exec_summary="retcode.json",
                 stdout="stdout.txt",
                 stderr="stderr.txt",
                 push=[{"src": "map-out", "dest": "map-out", "isDir": True},
                       {"src": "results", "dest": "results", "isDir": True},
                       {"src": "stdout.txt", "dest": "logs/"+index+"/stdout.txt", "isDir": False},
                       {"src": "stderr.txt", "dest": "logs/"+index+"/stderr.txt", "isDir": False},])

            config_url = push_str_to_cas(remote, json.dumps(config))
            sge_job_ids.append( self.submit_config(remote.remote_url+"/"+config_url) )

        return sge_job_ids

    def submit_gather(self, gather_fn, remote, rcode):
        r_script = self.generate_r_script(rcode, "phlock.exec.gather(\"{}\")".format(gather_fn))
        script_url = push_str_to_cas(remote, r_script)

        config = dict(
            remote_url = remote.remote_url,
             pull=[{"src": "shared", "dest": "shared", "isDir": True},
                   {"src": "map-out", "dest": "map-out", "isDir": True},
                   {"src": script_url, "dest": "script.R", "isDir": False},],
             mkdir=["results"],
             command=["Rscript", "script.R"],
             exec_summary="retcode.json",
             stdout="stdout.txt",
             stderr="stderr.txt",
             push=[{"src": "results", "dest": "results", "isDir": True},
                   {"src": "retcode.json", "dest": "completed/gather", "isDir": False},
                   {"src": "stdout.txt", "dest": "logs/gather/stdout.txt", "isDir": False},
                   {"src": "stderr.txt", "dest": "logs/gather/stderr.txt", "isDir": False},])

        config_url = push_str_to_cas(remote, json.dumps(config))
        sge_job_id = self.submit_config(remote.remote_url+"/"+config_url)
        return [sge_job_id]

import sqlite3

CREATE_STATEMENTS = ["CREATE TABLE JOB (FLOCK_ID INTEGER PRIMARY KEY AUTOINCREMENT, FN_PREFIX STRING, DOCKER_IMG STRING, REMOTE_URL STRING, STATE STRING, SGE_JOB_IDS STRING, MAX_JOBS INTEGER, RCODE_URL STRING, LOCAL_DIR STRING)"]

class FlockClient:
    def __init__(self, sge_exec_client, db_filename):
        self.sge_exec_client = sge_exec_client
        self.remote_url = sge_exec_client.remote_url
        new_db = not os.path.exists(db_filename)
        self.connection = sqlite3.connect(db_filename)
        c = self.connection.cursor()
        if new_db:
            for stmt in CREATE_STATEMENTS:
                c.execute(stmt)
        c.close()
        self.scatter_gather = ScatterGather(self._exec_fn)

    def _exec_fn(self, command):
        print("command:", " ".join(command))
        raise Exception("unimp")

    def _next_step(self, flock_id):
        fn_prefix, docker_img, remote_url, max_jobs, rcode_url, local_dir = self._get_job_params(flock_id)
        state, _ = self._get_state(flock_id)
        remote = Remote(remote_url, local_dir)

        # verify the current state completed successfully
        self.scatter_gather.check_state_complete(remote, state, max_jobs)

        scatter_fn = fn_prefix + ".scatter"
        map_fn = fn_prefix +".map"
        gather_fn = fn_prefix +".gather"

        rcode = remote.download_as_str(rcode_url)

        new_jobs = self.scatter_gather.do_scatter(scatter_fn, remote, rcode)
        if new_jobs is not None:
            return "scatter", new_jobs

        self.scatter_gather.do_map(map_fn, remote, rcode, max_jobs)
        if new_jobs is not None:
            return "map", new_jobs

        self.scatter_gather.do_gather(gather_fn, remote, rcode)
        if new_jobs is not None:
            return "gather", new_jobs

        return "complete", []

    def _get_job_params(self, flock_id):
        c = self.connection.cursor()
        try:
            c.execute("SELECT FN_PREFIX, DOCKER_IMG, REMOTE_URL, MAX_JOBS, RCODE_URL, LOCAL_DIR FROM JOB WHERE FLOCK_ID = ?", [flock_id])
            fn_prefix, docker_img, remote_url, max_jobs, rcode_url, local_dir = c.fetchone()
        finally:
            c.close()
        return fn_prefix, docker_img, remote_url, max_jobs, rcode_url, local_dir

    def _get_state(self, flock_id):
        c = self.connection.cursor()
        try:
            c.execute("SELECT STATE, SGE_JOB_IDS FROM JOB WHERE FLOCK_ID = ?", [flock_id])
            state, sge_job_ids_str = c.fetchone()
        finally:
            c.close()
        return state, json.loads(sge_job_ids_str)

    def _update_state(self, flock_id, state, sge_job_ids):
        for x in sge_job_ids:
            assert x is not None

        sge_job_ids_str = json.dumps(sge_job_ids)
        c = self.connection.cursor()
        try:
            c.execute("UPDATE JOB SET STATE = ?, SGE_JOB_IDS = ? WHERE FLOCK_ID = ?", [state, flock_id, sge_job_ids_str])
        finally:
            c.close()

    def _create_flock_job(self, docker_img, remote_url, rcode_url, fn_prefix, local_dir):
        c = self.connection.cursor()
        try:
            c.execute("INSERT INTO JOB (STATE, FN_PREFIX, DOCKER_IMG, REMOTE_URL, MAX_JOBS, RCODE_URL, SGE_JOB_IDS, LOCAL_DIR) values (?, ?, ?, ?, ?, ?, ?, ?)",
                      ["created", fn_prefix, docker_img, remote_url, None, rcode_url, "[]", local_dir])
            flock_id = c.lastrowid
        finally:
            c.close()
        return flock_id

    def _update(self, flock_id):
        state, running_jobs = self._get_state(flock_id)

        # go through all sge jobs and find out what's still outstanding
        remaining = []
        for sge_id in running_jobs:
            sge_state = self.sge_exec_client.get_state(sge_id)
            if sge_state != exec_client.SGE_STATUS_COMPLETE:
                remaining.append(sge_id)

        if len(remaining) == 0:
            state, remaining = self._next_step(flock_id)

        self._update_state(flock_id, state, remaining)

        return state

    def preprocess_inputs(self, resolver, inputs):
        result, sge_resolver = self.sge_exec_client.preprocess_inputs(resolver, inputs)
        return result, sge_resolver

    def execute(self, job_id, docker_img, fn_prefix, scripts, local_dir):
        rcode = []
        for script in scripts:
            if isinstance(script, parser.FlockInclude):
                with open(script.path, "rt") as fd:
                    rcode.append(fd.read())
            else:
                rcode.append(script)

        remote = helper.Remote(self.remote_url, ".")
        rcode_url = remote.remote_url + "/" + helper.push_str_to_cas(remote, "\n".join(rcode))

        job_remote_url = "{}/{}".format(self.remote_url, job_id)
        flock_id = self._create_flock_job(docker_img, job_remote_url, rcode_url, fn_prefix, local_dir)
        self._update(flock_id)

        return FlockExecution(flock_id, self)

    def get_state(self, flock_id):
        return self._update(flock_id)

    def reattach(self, external_ref):
        d = json.loads(external_ref)
        flock_id = d['flock_id']
        state, sge_job_ids = self._get_state(flock_id)
        for sge_job_id in sge_job_ids:
            self.sge_exec_client._saw_job_id(sge_job_id, exec_client.SGE_STATUS_SUBMITTED)

        return FlockExecution(flock_id, self)

class FlockExecution:
    def __init__(self, flock_id, client):
        self.flock_id = flock_id
        self.client = client
        self.extern_ref = {"flock_id": flock_id}

    def cancel(self):
        raise Exception("unimp")

    def get_state_label(self):
        return "Flock-"+self.client.get_state(self.flock_id)

    def get_external_id(self):
        return json.dumps(self.extern_ref)

    def _log_failure(self, msg):
        # TODO: Add dumping of stderr,stdout
        raise Exception("unimp")

    def get_completion(self):
        failure, outputs = self._get_completion()
        if failure is not None:
            self._log_failure(failure)
        return failure, outputs

    def _get_completion(self):
        state = self.client.get_state(self.flock_id)

        if state == "complete":
            return None, outputs
        elif state == "failed":
            return failure, None

        return None, None
