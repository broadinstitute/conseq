import json
import datetime
import subprocess
import jinja2
import os
import time
import textwrap
import logging
import tempfile

from collections import namedtuple

from . import dlcache
from . import dep
from . import depfile
from . import pull_url

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

def exec_script(name, id, language, job_dir, script_name, outputs):
    stdout_path = os.path.join(job_dir, "stdout.txt")
    stderr_path = os.path.join(job_dir, "stderr.txt")
    # results_path = os.path.join(job_dir, "results.json")

    script_name = os.path.abspath(script_name)
    stdout_path = os.path.abspath(stdout_path)
    stderr_path = os.path.abspath(stderr_path)
    retcode_path = os.path.abspath(os.path.join(job_dir, "retcode.txt"))

    env = os.environ.copy()

    if language in ['python']:
        cmd = "cd {job_dir} ; {language} {script_name} > {stdout_path} 2> {stderr_path} ; echo $? > {retcode_path}".format(**locals())

        if ("PYTHONPATH" in env):
            env['PYTHONPATH'] = env['PYTHONPATH'] + ":" + os.path.abspath(".")
        else:
            env['PYTHONPATH'] = os.path.abspath(".")
    elif language in ['shell']:
        cmd = "cd {job_dir} ; bash {script_name} > {stdout_path} 2> {stderr_path} ; echo $? > {retcode_path}".format(**locals())
    elif language in ['R']:
        cmd = "cd {job_dir} ; Rscript {script_name} > {stdout_path} 2> {stderr_path} ; echo $? > {retcode_path}".format(**locals())
    else:
        raise Exception("unknown language: {}".format(language))

    log.debug("executing: %s", cmd)

    proc = subprocess.Popen(['bash', '-c', cmd], env=env)
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

def execute(name, pull, jinja2_env, id, job_dir, inputs, rule):
    language = rule.language
    script_body = rule.script
    assert isinstance(inputs, dict)
    inputs = dict([(k, localize_filenames(pull, job_dir, v)) for k,v in inputs.items()])

    log.info("Executing %s with inputs %s", name, inputs)

    formatted_script_body = jinja2_env.from_string(script_body).render(inputs=inputs)
    formatted_script_body = textwrap.dedent(formatted_script_body)

    script_name = os.path.join(job_dir, "script")
    with open(script_name, "w") as fd:
        fd.write(formatted_script_body)
    execution = exec_script(name,
                       id,
                       language,
                       job_dir,
                       script_name,
                       rule.outputs)
    return execution


    # def __init__(self, transform, id, job_dir, results_path, proc, outputs):
    #     self.transform = transform
    #     self.id = id
    #     self.proc = proc
    #     self.results_path = results_path
    #     self.job_dir = job_dir
    #     self.outputs = outputs

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

def reattach(j, rules_by_name):
    pending_jobs = j.get_pending()
    executing = []
    for e in pending_jobs:
        if e.exec_xref != None:
            rule = rules_by_name[e.transform]
            ee = Execution(e.transform, e.id, e.job_dir, ProcStub(e.exec_xref), rule.outputs)
            executing.append(ee)
            log.warn("Reattaching existing job {}: {}".format(e.transform, e.exec_xref))
        else:
            log.warn("Canceling {}".format(e.id))
            j.cancel_execution(e.id)
    return executing

def main_loop(j, new_object_listener, rule_by_name, working_dir, executing):
    active_job_ids = set([e.id for e in executing])

    jinja2_env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    puller = pull_url.Pull()
    cache = dlcache.open_dl_db(working_dir+"/cache.sqlite3")

    def pull(url):
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

            rule = rule_by_name[job.transform]
            e = execute(job.transform, pull, jinja2_env, job.id, job_dir, dict(job.inputs), rule)
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

def to_template(rule):
    queries = []
    for name, spec in rule.inputs:
        assert name != ""
        queries.append(dep.ForEach(name, spec))
    return dep.Template(queries, [], rule.name)

def parse(filename):
    with open(filename) as f:
        text = f.read()
    parser = depfile.depfileParser(parseinfo=False)
    return parser.parse(
        text,
        "declarations",
        filename=filename,
        trace=False,
        nameguard=None,
        semantics = Semantics())

def add_xref(j, xref):
    timestamp = datetime.datetime.now().isoformat()
    d = dict(xref.obj)
    d["filename"] = {"$xref_url": xref.url}
    return j.add_obj(timestamp, d, overwrite=False)

def read_deps(filename, j):
    rule_by_name = {}
    p = parse(filename)
    for dec in p:
        if isinstance(dec, XRef):
            add_xref(j, dec)
        else:
            assert isinstance(dec, Rule)
            #print("adding transform", dec.name)
            rule_by_name[dec.name] = (dec)
    return rule_by_name

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

def main(depfile, state_dir, forced_targets):
    if not os.path.exists(state_dir):
        os.makedirs(state_dir)
    working_dir = os.path.join(state_dir, "working")
    if not os.path.exists(working_dir):
        os.makedirs(working_dir)
    db_path = os.path.join(state_dir, "db.sqlite3")
    j = dep.open_job_db(db_path)

    for target in forced_targets:
        #assert target in rule_by_name
        count = j.invalidate_rule_execution(target)
        log.info("Cleared %d old executions of %s", count, target)

    rule_by_name = read_deps(depfile, j)

    executing = reattach(j, rule_by_name)

    for dec in rule_by_name.values():
        if not (isinstance(dec, Rule)):
            continue
        j.add_template(to_template(dec))

    def new_object_listener(obj):
        timestamp = datetime.datetime.now().isoformat()
        j.add_obj(timestamp, obj)
    try:
        main_loop(j, new_object_listener, rule_by_name, working_dir, executing)
    except FatalUserError as e:
        print("Error: {}".format(e))

class XRef:
    def __init__(self, url, obj):
        self.url = url
        self.obj = obj

class Rule:
    def __init__(self, name):
        self.name = name
        self.inputs = []
        self.outputs = None
        self.options = []
        self.script = None
        assert self.name != "" and self.name != " "

    @property
    def language(self):
        if "exec-python" in self.options:
            return "python"
        elif "exec-R" in self.options:
            return "R"
        else:
            return "shell"

    def __repr__(self):
        return "<Rule {} inputs={} options={}>".format(self.name, self.inputs, self.options)

def unquote(s):
    if len(s) > 0 and s[:3] == '"""':
        assert s[-3:] == '"""'
        return s[3:-3]
    assert s[0] == '"'
    assert s[-1] == '"'
    return s[1:-1]

InputSpec = namedtuple("InputSpec", ["variable", "json_obj"])

class Semantics(object):
    def statement(self, ast):
#        print("statement:", repr(ast))
        return tuple(ast)

    def input_spec(self, ast):
        return InputSpec(ast[0], ast[2])

    def statements(self, ast):
#        print("statements:", repr(ast))
        return ast

    def json_name_value_pair(self, ast):
        return (ast[0], ast[2])

    def json_obj(self, ast):
        #print("json_obj", ast)
        pairs = [ast[1]]
        rest = ast[2]
        for x in range(0, len(rest), 2):
            pairs.append(rest[x+1])
        #print("after json_obj", pairs)
        return dict(pairs)

    def xref(self, ast):
        #print("xref ast", ast)
        return XRef(ast[1],ast[2])

    def rule(self, ast):
        #print("rule", repr(ast))
        rule_name = ast[1]
        statements = ast[3]
        #print("rule: {}".format(repr(ast)))
        rule = Rule(rule_name)
        for statement in statements:
            if statement[0] == "inputs":
                rule.inputs = statement[2]
            elif statement[0] == "outputs":
                rule.outputs = statement[2]
            elif statement[0] == "script":
                rule.script = statement[2]
            elif statement[0] == "options":
                #print("----> options", statement)
                options = [statement[2]]
                rest = statement[3]
                for i in range(0,len(rest),2):
                    options.append(rest[1])
                rule.options = options
            else:
                raise Exception("unknown {}".format(statement[0]))
        #print("rule:", repr(rule))
        return rule

    def quoted_string(self, ast):
        return unquote(ast)

    def input_specs(self, ast):
        specs = [ast[0]]
        rest = ast[1]
        for i in range(0,len(rest),2):
            specs.append(rest[1])
        return specs

    def output_specs(self, ast):
        specs = [ast[0]]
        rest = ast[1]
        for i in range(0,len(rest),2):
            specs.append(rest[1])
        return specs


