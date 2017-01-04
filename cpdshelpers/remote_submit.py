import collections
import json
import requests
import time
import os
import logging

log = logging.getLogger("cluseruiclient")

try:
    from ConfigParser import ConfigParser
except ImportError:
    from configparser import ConfigParser

RunConfig = collections.namedtuple("RunConfig", ["key", "parameters"])

class ClusterUIClient:
    """ Class which allows submission/monitoring of jobs to an instance of the ClusterUI.  
        To initialize, you need need to provide the path to a config file that contains the following:
        
        [clusterui]
        # the url that the cluster UI instance is running on
        url=http://datasci-dev.broadinstitute.org:9922
        # the authorization token to use.  This is set by the variable BEARER_TOKENS in ~/.clusterui.config corresponding the the cluster ui instance
        token=abcdefghi
    """
    def __init__(self, config_filename=os.path.expanduser("~/.clusteruiclient")):
        c = ConfigParser()
        c.read(config_filename)
        self.url = c.get("clusterui", "url")
        self.token = c.get("clusterui", "token")
        self.auth_header = dict(Authorization="Bearer "+self.token)

    def get_existing_runs(self, archive=None):
        """ Return a list of runs (as a list of dictionaries).  If no archive is specified, then returns just those on the main jobs page """
        url = self.url+"/api/list-runs"
        if archive != None:
            url += "?archive="+archive
        r = requests.get(url, headers=self.auth_header)
        return r.json()['runs']

    def archive(self, job_ids, destination):
        """ Move the jobs with the given id to the archive specified by "destination" """
        args = {"job-ids": job_ids, "destination": destination}
        r = requests.post(self.url+"/api/archive-jobs", headers=self.auth_header, json=args)
        return r.json()

    def submit_run(self, template_str, repo, branch, config):
        job = dict(
            template=template_str,
            config_defs = configset_with_singleton(config),
            repo = repo,
            branch = branch
        )

        r = requests.post(self.url+"/api/submit-job", headers=self.auth_header, json=job)
        result =  r.json()
        success = result['success']
        if not success:
            raise ExceptionDetails("clusterui reports submittion failure", stderr=result['stderr'], stdout=result['stdout'])

    def execute_runs(self, template_str, repo, branch, parameters_for_runs, dest_archive, stable_props = ['name','fitSettings','bdpclass','permutations','celllineSubset','predictiveFeatureSubset'],
        poll_delay=60):
        """
        Execute a job via clusterUI.  Does not submit job if it can find an identical job already in clusterui (as defined by "stable_props")

        After jobs are completed successfully, archives jobs based on "dest_archive".

        :param template_str: Template to use
        :param repo: git repo to pull from
        :param branch: git branch
        :param parameters_for_runs: list of dictionaries
        :param dest_archive: Name of archive to store in once job is complete
        :param stable_props: The property names which must match for this to be considered the same as an existing run
        :param poll_delay: How frequently to check whether the jobs are complete
        :return:
        """
        return execute_runs(self, template_str, repo, branch, parameters_for_runs, dest_archive, stable_props, poll_delay)

def make_key(parameters, stable_props):
    return json.dumps(tuple([parameters[x] for x in stable_props]))

def make_run_config(_parameters, stable_props):
    parameters = dict(_parameters)
    for key in ["branch","parameter_hash","repo","run_id","sha","username","run-hash"]:
        if key in parameters:
            del parameters[key]
    stable_parameters = json.dumps(parameters, sort_keys=True).encode("utf-8")
    final_parameters = dict(_parameters)
    return RunConfig(make_key(parameters, stable_props), final_parameters)

# convert a single dict into a list of dicts, where each value is also a dict, which
# is what the submit job api wants.
def configset_with_singleton(config):
    result = dict( [(k, [v]) for k, v in config.items()] )
    return [result]

class ExceptionDetails(Exception):
    def __init__(self, msg, stderr, stdout):
        super(Exception, self).__init__(msg)
        self.stderr = stderr
        self.stdout = stdout
    def __repr__(self):
        return "ExceptionDetails: "+self.message+"\nstdout:\n"+self.stdout+"\nstderr:\n"+self.stderr

def resolve_runs(client, parameters_for_runs, template_str, stable_props, archive=None):
    existing_runs = client.get_existing_runs(archive)
    existing_runs_by_key = {}
    for x in existing_runs:
        run_params = x['parameters']
        key = make_key(run_params, stable_props)
        existing_runs_by_key[key] = x

    runs = [make_run_config(x, stable_props) for x in parameters_for_runs]

    existing = []
    missing = []
    for x in runs:
        if x.key in existing_runs_by_key:
            existing_run = existing_runs_by_key[x.key]
            existing.append(existing_run)
        else:
            missing.append(x)
    return missing, existing

def is_finished(x):
    for in_progress_status in ["STARTED", "WAITING", "READY", "SUBMITTED"]:
        if in_progress_status in x["status"]:
            return False
    return True

def completed_successfully(x):
    return "COMPLETED" in x["status"] and len(x['status']) == 1

def execute_runs(client, template_str, repo, branch, parameters_for_runs, dest_archive, stable_props, poll_delay):
    """ Execute one or more runs as specified by the "parameters_for_runs".  If there already exists a job
    with the specified properties (only "stable_props" are checked for a match), a new job will not be 
    spawned.  Instead, it will monitor the existing job and wait for it to complete.

    Once there are no jobs still running, an exception will be thrown if any jobs had failed.

    If there was no error, jobs will be archived in dest_archive.  

    Upon all jobs successfully completing, returns a list of dicts containing the run properties.
    """

    # drop parameters which were already run and archived
    missing, existing = resolve_runs(client, parameters_for_runs, template_str, stable_props, dest_archive)
    parameters_for_runs = [x.parameters for x in missing]
    log.info("Skipping {} runs which were already present in {}".format(len(existing), dest_archive))
    existing_in_archive = existing    
    
    log.info("executing {} runs".format(len(parameters_for_runs)))
    missing, existing = resolve_runs(client, parameters_for_runs, template_str, stable_props)
    for x in missing:
        log.warn("Submitting {}".format(x))
        client.submit_run(template_str, repo, branch, x.parameters)

    while True:
        missing, existing = resolve_runs(client, parameters_for_runs, template_str, stable_props)
        if len(missing) > 0:
            raise Exception("Jobs disappeared: {}".format(missing))

        still_running = 0
        completed = 0
        for x in existing:
            if not is_finished(x):
                still_running += 1
            else:
                completed += 1
        if still_running == 0:
            break

        log.info("{} jobs completed, {} jobs running".format(completed, still_running))
        time.sleep(poll_delay)
        log.info("Polling...")
    failed = 0
    for x in existing:
       if not completed_successfully(x):
          failed += 1
    assert failed == 0, "Not all jobs completed successfully: {} jobs failed".format(failed)
    log.info("finished")

    #print("existing={}".format(existing))
    if len(existing) > 0:
        job_ids = [x['name'] for x in existing]
        client.archive(job_ids, dest_archive)
    existing_in_archive = existing_in_archive + existing
    return existing_in_archive
