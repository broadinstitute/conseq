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

class FatalUserError(Exception):
    pass

class Execution:
    def __init__(self, transform, id, job_dir, results_path, proc, outputs):
        self.transform = transform
        self.id = id
        self.proc = proc
        self.results_path = results_path
        self.job_dir = job_dir
        self.outputs = outputs

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

        if self.outputs != None:
            results = {"outputs": self.outputs}
        else:
            if not os.path.exists(self.results_path):
                raise FatalUserError("rule {} completed successfully, but no results.json file written to working directory".format(self.transform))

            with open(self.results_path) as fd:
                results = json.load(fd)

        print("----> results", results)
        outputs = [self._resolve_filenames(o) for o in results['outputs']]
        return outputs

def exec_script(name, id, language, job_dir, script_name, stdout_path, stderr_path, results_path, outputs):
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
    return Execution(name, id, job_dir, results_path, proc, outputs)

import tempfile

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

    print("Executing {} with inputs {}".format(name, inputs))

    formatted_script_body = jinja2_env.from_string(script_body).render(inputs=inputs)
    formatted_script_body = textwrap.dedent(formatted_script_body)

    script_name = os.path.join(job_dir, "script")
    with open(script_name, "w") as fd:
        fd.write(formatted_script_body)
    return exec_script(name,
                       id,
                       language,
                       job_dir,
                       script_name,
                       os.path.join(job_dir, "stdout.txt"),
                       os.path.join(job_dir, "stderr.txt"),
                       os.path.join(job_dir, "results.json"),
                       rule.outputs)

from . import dlcache

def main_loop(j, new_object_listener, rule_by_name, working_dir):
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

            job_dir = working_dir + "/run-" + datetime.datetime.now().isoformat() + "-" + str(job.id)
            if not os.path.exists(job_dir):
                os.makedirs(job_dir)

            rule = rule_by_name[job.transform]
            e = execute(job.transform, pull, jinja2_env, job.id, job_dir, dict(job.inputs), rule)
            executing.append(e)

        for i, e in reversed(list(enumerate(executing))):
            completion = e.get_completion()
            if completion == None:
                continue

            del executing[i]
            timestamp = datetime.datetime.now().isoformat()
            j.record_completed(timestamp, e.id, dep.STATUS_COMPLETED, completion)
            did_useful_work = True
        
        if not did_useful_work:
            time.sleep(0.5)

def to_template(rule):
    queries = []
    print("to_template", rule.inputs)
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
        trace=True,
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
    for dec in p:
        if not (isinstance(dec, Rule)):
            continue
        j.add_template(to_template(dec))
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

def main(depfile, state_dir):
    if not os.path.exists(state_dir):
        os.makedirs(state_dir)
    working_dir = os.path.join(state_dir, "working")
    if not os.path.exists(working_dir):
        os.makedirs(working_dir)
    db_path = os.path.join(state_dir, "db.sqlite3")
    j = dep.open_job_db(db_path)
    rule_by_name = read_deps(depfile, j)
    def new_object_listener(obj):
        timestamp = datetime.datetime.now().isoformat()
        j.add_obj(timestamp, obj)
    try:
        main_loop(j, new_object_listener, rule_by_name, working_dir)
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
        self.outputs = []
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

from collections import namedtuple
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


