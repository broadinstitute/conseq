import json
import datetime
import subprocess
import jinja2
import os
import time
import textwrap

from . import dep
from . import depfile
from . import pull_url

class Execution:
    def __init__(self, id, job_dir, results_path, proc):
        self.id = id
        self.proc = proc
        self.results_path = results_path
        self.job_dir = job_dir

    def _resolve_filenames(self, props):
        props_copy = {}
        for k, v in props.items():
            if isinstance(v, dict) and "$filename" in v:
                v = {"$filename": self.job_dir + "/" + v["$filename"]}
            props_copy[k] = v
        return props_copy

    def get_completion(self):
        retcode = self.proc.poll()
   
        if retcode == None:
            return None
        
        if retcode != 0:
            raise Exception("failed with {}".format(retcode))

        with open(self.results_path) as fd:
            results = json.load(fd)
        print("----> results", results)
        outputs = [self._resolve_filenames(o) for o in results['outputs']]
        return outputs

def exec_script(id, language, job_dir, script_name, stdout_path, stderr_path, results_path):
    script_name = os.path.abspath(script_name)
    stdout_path = os.path.abspath(stdout_path)
    stderr_path = os.path.abspath(stderr_path)
    if language in ['python']:
        cmd = "cd {job_dir} ; {language} {script_name} > {stdout_path} 2> {stderr_path}".format(**locals())
    elif language in ['shell']:
        cmd = "cd {job_dir} ; bash {script_name} > {stdout_path} 2> {stderr_path}".format(**locals())
    elif language in ['R']:
        cmd = "cd {job_dir} ; Rscript {script_name} > {stdout_path} 2> {stderr_path}".format(**locals())
    else:
        raise Exception("unknown language: {}".format(language))
    print("executing:", cmd)
    env = os.environ.copy()
    if ("PYTHONPATH" in env):
        env['PYTHONPATH'] = env['PYTHONPATH'] + ":" + os.path.abspath(".")
    else:
        env['PYTHONPATH'] = os.path.abspath(".")
    proc = subprocess.Popen(['bash', '-c', cmd], env=env)
    return Execution(id, job_dir, results_path, proc)

import tempfile

def localize_filenames(pull, job_dir, props):
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

def execute(pull, jinja2_env, id, language, job_dir, script_body, inputs):
    assert isinstance(inputs, dict)
    inputs = dict([(k, localize_filenames(pull, job_dir, v.props)) for k,v in inputs.items()])

    formatted_script_body = jinja2_env.from_string(script_body).render(inputs=inputs)
    formatted_script_body = textwrap.dedent(formatted_script_body)

    os.makedirs(job_dir)
    script_name = os.path.join(job_dir, "script")
    with open(script_name, "w") as fd:
        fd.write(formatted_script_body)
    return exec_script(id,
                       language,
                       job_dir,
                       script_name,
                       os.path.join(job_dir, "stdout.txt"),
                       os.path.join(job_dir, "stderr.txt"),
                       os.path.join(job_dir, "results.json"))

from . import dlcache

def main_loop(j, new_object_listener, script_by_name, working_dir):
    jinja2_env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    puller = pull_url.Pull()
    cache = dlcache.open_dl_db(working_dir+"/cache.sqlite3")

    def pull(url):
        print("pull ----------------------------")
        dest_filename = cache.get(url)
        if dest_filename == None:
            dest_filename = tempfile.NamedTemporaryFile(delete=False, dir=working_dir).name
            puller.pull(url, dest_filename)
            cache.put(url, dest_filename)
        return dest_filename

    run_dir = "run-" + datetime.datetime.now().isoformat()
    os.makedirs(run_dir)
    executing = []
    active_job_ids = set()

    while True:
        pending_jobs = j.get_pending()
        if len(executing) == 0 and len(pending_jobs) == 0:
            break
        print("executing", len(executing), "pending", len(pending_jobs))

        did_useful_work = False
        for job in pending_jobs:
            assert isinstance(job, dep.RulePending)
            if job.id in active_job_ids:
                continue
            active_job_ids.add(job.id)
            did_useful_work = True

            job_dir = run_dir + "/"+str(job.id)
            language, script = script_by_name[job.transform]
            e = execute(pull, jinja2_env, job.id, language, job_dir, script, dict(job.inputs))
            executing.append(e)

        for i, e in reversed(list(enumerate(executing))):
            completion = e.get_completion()
            if completion == None:
                continue

            del executing[i]
            timestamp = datetime.datetime.now().isoformat()
            j.record_completed(timestamp, e.id, dep.COMPLETED, completion)
            did_useful_work = True
        
        if not did_useful_work:
            time.sleep(0.5)

def to_template(rule):
    queries = []
    for name, spec in rule.inputs:
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
        whitespace="",
        nameguard=None,
        semantics = Semantics())

def add_xref(j, xref):
    timestamp = datetime.datetime.now().isoformat()
    d = dict(xref.obj)
    d["filename"] = {"$xref_url": xref.url}
    return j.add_obj(timestamp, d, overwrite=False)

def read_deps(filename, j):
    script_by_name = {}
    p = parse(filename)
    print("------>", repr(p))
    for dec in p:
        if isinstance(dec, XRef):
            add_xref(j, dec)
        else:
            assert isinstance(dec, Rule)
            script_by_name[dec.name] = (dec.language, dec.script)
    for dec in p:
        if not (isinstance(dec, Rule)):
            continue
        j.add_template(to_template(dec))
    return script_by_name

def dot_cmd(state_dir):
    print("dot")
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    print(j.to_dot())

def list_cmd(state_dir):
    print("list")
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    j.dump()

def main(depfile, state_dir):
    print("state", state_dir)
    if not os.path.exists(state_dir):
        os.makedirs(state_dir)
    working_dir = os.path.join(state_dir, "working")
    if not os.path.exists(working_dir):
        os.makedirs(working_dir)
    db_path = os.path.join(state_dir, "db.sqlite3")
    print("db_path", db_path)
    j = dep.open_job_db(db_path)
    print('x')
    script_by_name = read_deps(depfile, j)
    def new_object_listener(obj):
        timestamp = datetime.datetime.now().isoformat()
        j.add_obj(timestamp, obj)
    main_loop(j, new_object_listener, script_by_name, working_dir)

class XRef:
    def __init__(self, url, obj):
        self.url = url
        self.obj = obj

class Rule:
    def __init__(self, name):
        self.name = name
        self.inputs = []
        self.outputs = []
        self.options = []
        self.script = None

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

class Semantics(object):
    def statement(self, ast):
#        print("statement:", repr(ast))
        return tuple(ast)

    def statements(self, ast):
#        print("statements:", repr(ast))
        return ast

    def json_name_value_pair(self, ast):
        return (ast[0], ast[4])

    def json_obj(self, ast):
        rest = ast[4]
        obj = dict( [ast[2]] + [rest[x] for x in range(1, len(rest), 3)] )
        #print("json_obj", obj)
        return obj

    def xref(self, ast):
        return XRef(ast[3],ast[5])

    def rule(self, ast):
        #print("rule", repr(ast))
        rule_name = ast[3]
        statements = ast[7]
        #print("rule: {}".format(repr(ast)))
        rule = Rule(rule_name)
        for statement in statements:
            if statement[0] == "inputs":
                rule.inputs = statement[4]
            elif statement[0] == "outputs":
                rule.outputs = statement[4]
            elif statement[0] == "script":
                rule.script = statement[4]
            elif statement[0] == "options":
                #print("----> options", statement)
                rule.options = [statement[4]] + list(statement[5])
            else:
                raise Exception("unknown {}".format(statement[0]))
        print("rule:", repr(rule))
        return rule

    def quoted_string(self, ast):
        return unquote(ast)

    def input_specs(self, ast):
        #print("input_specs", repr(ast))
        ast = ast[0:5] + ast[5]
        #print("input_specs appened", repr(ast))
        return [ (ast[i], ast[i+4]) for i in range(0, len(ast), 7)]

    def output_specs(self, ast):
        ast = ast[0:5] + ast[5]
        return [ (ast[i], ast[i+4]) for i in range(0, len(ast), 7)]

