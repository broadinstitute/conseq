import json
import datetime
import subprocess
import jinja2
import os
import time
import textwrap
import logging
import tempfile
import collections

from . import dlcache
from . import dep
from . import pull_url
from . import parser

log = logging.getLogger(__name__)

class FatalUserError(Exception):
    pass

class JobFailedError(FatalUserError):
    pass

class Execution:
    def __init__(self, transform, id, job_dir, proc, outputs):
        self.transform = transform
        self.id = id
        self.proc = proc
        self.job_dir = job_dir
        self.outputs = outputs
        assert job_dir != None

    def _resolve_filenames(self, props):
        props_copy = {}
        for k, v in props.items():
            if isinstance(v, dict) and "$filename" in v:
                v = {"$filename": self.job_dir + "/" + v["$filename"]}
            props_copy[k] = v
        return props_copy

    @property
    def results_path(self):
        return os.path.join(self.job_dir, "results.json")

    def get_completion(self):
        retcode = self.proc.poll()

        # if self.backend == "local":
        #     pid = int(self.backend_id)
        #     running = True
        #     try:
        #         os.kill(pid, 0)
        #     except OSError:
        #         running = False
        #
        #     if running:
        # else:
        #     raise Exception("unknown backend {}".format(self.backend))

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
        return None, outputs

def exec_script(name, id, language, job_dir, script_name, postscript_name, outputs):
    stdout_path = os.path.join(job_dir, "stdout.txt")
    stderr_path = os.path.join(job_dir, "stderr.txt")
    # results_path = os.path.join(job_dir, "results.json")

    script_name = os.path.abspath(script_name)
    stdout_path = os.path.abspath(stdout_path)
    stderr_path = os.path.abspath(stderr_path)
    retcode_path = os.path.abspath(os.path.join(job_dir, "retcode.txt"))

    env = os.environ.copy()
    if ("PYTHONPATH" in env):
        env['PYTHONPATH'] = env['PYTHONPATH'] + ":" + os.path.abspath(".")
    else:
        env['PYTHONPATH'] = os.path.abspath(".")

    wrapper_path = os.path.join(job_dir, "wrapper.sh")
    with open(wrapper_path, "w") as fd:
        fd.write("cd {job_dir}\n".format(**locals()))

        if language in ['python']:
            cmd = "{language} {script_name}".format(**locals())
        elif language in ['shell']:
            cmd = "bash {script_name}".format(**locals())
        elif language in ['R']:
            cmd = "Rscript {script_name}".format(**locals())
        else:
            raise Exception("unknown language: {}".format(language))

        if postscript_name != None:
            cmd += " && python {}".format(postscript_name)

        fd.write(cmd+"\n")
        fd.write("echo $? > {retcode_path}\n".format(**locals()))

    bash_cmd = "exec bash {wrapper_path} > {stdout_path} 2> {stderr_path}".format(**locals())
    log.debug("executing: %s", bash_cmd)
    proc = subprocess.Popen(['bash', '-c', bash_cmd], env=env)
    return Execution(name, id, job_dir, proc, outputs)

def _localize_filenames(pull, job_dir, props):
    props_copy = {}
    for k, v in props.items():
        if isinstance(v, dict):
            if "$filename" in v:
                v = os.path.relpath(v["$filename"], job_dir)
            elif "$xref_url" in v:
                url = v["$xref_url"]
                v = pull(url)
        props_copy[k] = v

    return props_copy

def localize_filenames(pull, job_dir, v):
    if isinstance(v, dep.Obj):
        return _localize_filenames(pull, job_dir, v.props)
    assert isinstance(v, tuple)
    return [_localize_filenames(pull, job_dir, x.props) for x in v]

class LazyConfig:
    def __init__(self, render_template, config_dict):
        self._config_dict = config_dict
        self._render_template = render_template

    def __getitem__(self, name):
        v = self._config_dict[name]
        return self._render_template(v)

def render_template(jinja2_env, template_text, config, **kwargs):
    kwargs = dict(kwargs)

    def render_template_callback(text):
        rendered = jinja2_env.from_string(text).render(**kwargs)
        return rendered

    kwargs["config"] = LazyConfig(render_template_callback, config)

    return render_template_callback(template_text)

def execute(name, pull, jinja2_env, id, job_dir, inputs, rule, config):
    language = rule.language
    assert isinstance(inputs, dict)
    inputs = dict([(k, localize_filenames(pull, job_dir, v)) for k,v in inputs.items()])

    log.info("Executing %s with inputs %s", name, inputs)

    def write_script(filename, script_body):
        formatted_script_body = render_template(jinja2_env, script_body, config=config, inputs=inputs)
        formatted_script_body = textwrap.dedent(formatted_script_body)

        script_name = os.path.join(job_dir, "script")
        with open(script_name, "w") as fd:
            fd.write(formatted_script_body)

        return script_name

    script_name = write_script("script", rule.script)
    postscript_name = None
    if rule.postscript != None:
        postscript_name = write_script("postscript", rule.postscript)

    execution = exec_script(name,
                       id,
                       language,
                       job_dir,
                       script_name,
                       postscript_name,
                       rule.outputs)
    return execution

class ProcStub:
    def __init__(self, xref):
        assert xref.startswith("PID:")
        self.pid = int(xref[4:])

    def poll(self):
        try:
            os.kill(self.pid, 0)
            return None
        except OSError:
            return 0

def reattach(j, rules):
    pending_jobs = j.get_pending()
    executing = []
    for e in pending_jobs:
        if e.exec_xref != None:
            rule = rules.get_rule(e.transform)
            ee = Execution(e.transform, e.id, e.job_dir, ProcStub(e.exec_xref), rule.outputs)
            executing.append(ee)
            log.warn("Reattaching existing job {}: {}".format(e.transform, e.exec_xref))
        else:
            log.warn("Canceling {}".format(e.id))
            j.cancel_execution(e.id)
    return executing

def main_loop(j, new_object_listener, rules, working_dir, executing):
    active_job_ids = set([e.id for e in executing])

    jinja2_env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    puller = pull_url.Pull()
    cache = dlcache.open_dl_db(working_dir+"/cache.sqlite3")

    def pull(url):
        # check to see if url is actual a file we can access.  If so, just return that path
        if os.path.exists(url):
            return os.path.abspath(url)

        dest_filename = cache.get(url)
        if dest_filename == None:
            dest_filename = tempfile.NamedTemporaryFile(delete=False, dir=working_dir).name
            puller.pull(url, dest_filename)
            cache.put(url, dest_filename)
        return dest_filename

    prev_msg = None
    while True:
        pending_jobs = j.get_pending()
        msg = "%d processes running, %d executions pending" % ( len(executing), len(pending_jobs) - len(executing) )
        if prev_msg != msg:
            log.info(msg)
        prev_msg = msg
        if len(executing) == 0 and len(pending_jobs) == 0:
            break

        did_useful_work = False
        for job in pending_jobs:
            assert isinstance(job, dep.RulePending)
            if job.id in active_job_ids:
                continue
            active_job_ids.add(job.id)
            did_useful_work = True

            job_dir = working_dir + "/run-" + datetime.datetime.now().isoformat() + "-" + str(job.id)
            if not os.path.exists(job_dir):
                os.makedirs(job_dir)

            rule = rules.get_rule(job.transform)
            e = execute(job.transform, pull, jinja2_env, job.id, job_dir, dict(job.inputs), rule, rules.get_vars())
            executing.append(e)
            j.update_exec_xref(e.id, "PID:{}".format(e.proc.pid), job_dir)

        for i, e in reversed(list(enumerate(executing))):
            failure, completion = e.get_completion()

            if failure == None and completion == None:
                continue

            del executing[i]
            timestamp = datetime.datetime.now().isoformat()

            if failure != None:
                log.error("Transform %s failed (job_dir=%s): %s", e.transform, e.job_dir, failure)
                j.record_completed(timestamp, e.id, dep.STATUS_FAILED, {})
            elif completion != None:
                j.record_completed(timestamp, e.id, dep.STATUS_COMPLETED, completion)

            did_useful_work = True
        
        if not did_useful_work:
            time.sleep(0.5)

def add_xref(j, xref):
    timestamp = datetime.datetime.now().isoformat()
    d = dict(xref.obj)
    d["filename"] = {"$xref_url": xref.url}
    return j.add_obj(timestamp, d, overwrite=False)

class Rules:
    def __init__(self):
        self.rule_by_name = {}
        self.vars = {}

    def set_var(self, name, value):
        self.vars[name] = value

    def get_vars(self):
        return dict(self.vars)

    def __iter__(self):
        return iter(self.rule_by_name.values())

    def get_rule(self, name):
        return self.rule_by_name[name]

    def set_rule(self, name, rule):
        if name in self.rule_by_name:
            raise Exception("Duplicate rules for {}".format(name))
        self.rule_by_name[name] = rule

    def merge(self, other):
        for name, rule in other.rule_by_name.items():
            self.set_rule(name, rule)
        self.vars.update(other.vars)

    def __repr__(self):
        return "<Rules vars:{}, rules:{}>".format(self.vars, list(self))

def read_deps(filename, j):
    rules = Rules()
    p = parser.parse(filename)
    for dec in p:
        if isinstance(dec, parser.XRef):
            add_xref(j, dec)
        elif isinstance(dec, parser.LetStatement):
            rules.set_var(dec.name, dec.value)
        elif isinstance(dec, parser.IncludeStatement):
            child_rules = read_deps(dec.filename, j)
            rules.merge(child_rules)
        else:
            assert isinstance(dec, parser.Rule)
            rules.set_rule(dec.name, dec)
    return rules

def rm_cmd(state_dir, dry_run, json_query, with_invalidate):
    query = json.loads(json_query)
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    for o in j.find_objs(query):
        print("rm", o)
        if not dry_run:
            j.remove_obj(o.id, with_invalidate)

def dot_cmd(state_dir):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    print(j.to_dot())

def list_cmd(state_dir):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    j.dump()


def to_template(rule):
    queries = []
    predicates = []
    pairs_by_var = collections.defaultdict(lambda: [])
    for bound_name, spec in rule.inputs:
        assert bound_name != ""

        constants = {}
        for prop_name, value in spec.items():
            if isinstance(value, parser.QueryVariable):
                pairs_by_var[value.name].append( (bound_name, prop_name) )
            else:
                constants[prop_name] = value
        queries.append(dep.ForEach(bound_name, constants))

    for var, pairs in pairs_by_var.items():
        predicates.append(dep.PropsMatch(pairs))

    return dep.Template(queries, predicates, rule.name)

def main(depfile, state_dir, forced_targets):
    if not os.path.exists(state_dir):
        os.makedirs(state_dir)
    working_dir = os.path.join(state_dir, "working")
    if not os.path.exists(working_dir):
        os.makedirs(working_dir)
    db_path = os.path.join(state_dir, "db.sqlite3")
    j = dep.open_job_db(db_path)

    for target in forced_targets:
        count = j.invalidate_rule_execution(target)
        log.info("Cleared %d old executions of %s", count, target)

    rules = read_deps(depfile, j)

    executing = reattach(j, rules)

    for dec in rules:
        if not (isinstance(dec, parser.Rule)):
            continue
        j.add_template(to_template(dec))

    def new_object_listener(obj):
        timestamp = datetime.datetime.now().isoformat()
        j.add_obj(timestamp, obj)
    try:
        main_loop(j, new_object_listener, rules, working_dir, executing)
    except FatalUserError as e:
        print("Error: {}".format(e))


