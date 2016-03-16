import json
import datetime
import subprocess
import jinja2
import os
import time
import textwrap
import logging
import collections
import shutil

from . import dep
from . import parser

log = logging.getLogger(__name__)

class FatalUserError(Exception):
    pass

class JobFailedError(FatalUserError):
    pass

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
        return None, outputs

def exec_script(name, id, language, job_dir, run_stmts, outputs, capture_output, prologue, desc_name):
    stdout_path = os.path.join(job_dir, "stdout.txt")
    stderr_path = os.path.join(job_dir, "stderr.txt")
    # results_path = os.path.join(job_dir, "results.json")

    stdout_path = os.path.abspath(stdout_path)
    stderr_path = os.path.abspath(stderr_path)
    retcode_path = os.path.abspath(os.path.join(job_dir, "retcode.txt"))

    wrapper_path = os.path.join(job_dir, "wrapper.sh")
    with open(wrapper_path, "w") as fd:
        fd.write("set -ex\n")
        fd.write("cd {job_dir}\n".format(**locals()))

        fd.write(prologue+"\n")

        for command in run_stmts:
            fd.write(command)
            fd.write(" &&\\\n")

        fd.write("true\n")
        fd.write("echo $? > {retcode_path}\n".format(**locals()))

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

class LazyConfig:
    def __init__(self, render_template, config_dict):
        self._config_dict = config_dict
        self._render_template = render_template

    def __getitem__(self, name):
        v = self._config_dict[name]
        return self._render_template(v)

def render_template(jinja2_env, template_text, config, **kwargs):
    assert isinstance(template_text, str)
    kwargs = dict(kwargs)

    def render_template_callback(text):
        try:
            rendered = jinja2_env.from_string(text).render(**kwargs)
            return rendered
        except jinja2.exceptions.UndefinedError:
            log.exception("Undefined value, applying {} to {}".format(kwargs, repr(text)))
            raise

    kwargs["config"] = LazyConfig(render_template_callback, config)

    return render_template_callback(template_text)

def flatten_parameters(d):
    pairs = []
    for k, v in d.items():
        if isinstance(v, dict) and len(v) == 1 and "$value" in v:
            v = v["$value"]
        elif isinstance(v, dict) and len(v) == 1 and "$filename" in v:
            v = os.path.abspath(v["$filename"])
        pairs.append( (k,v) )
    return dict(pairs)

def needs_resolution(obj):
    if not ("$xref_url" in obj):
        return False
    for v in obj.values():
        if isinstance(v, dict) and "$value" in v:
            return False
    return True

def preprocess_inputs(j, resolver, inputs):
    xrefs_resolved = [False]

    def resolve(obj_):
        assert isinstance(obj_, dep.Obj)
        obj = obj_.props
        if needs_resolution(obj):
            extra_params = resolver.resolve(obj["$xref_url"])
            obj_copy = dict(obj)
            for k, v in extra_params.items():
                obj_copy[k] = {"$value": v}
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

def execute(name, resolver, jinja2_env, id, job_dir, inputs, rule, config, capture_output):
    prologue = render_template(jinja2_env, config["PROLOGUE"], config)

    language = rule.language
    if rule.outputs == None:
        outputs = None
    else:
        outputs = [expand_outputs(jinja2_env, output, config, inputs=inputs) for output in rule.outputs]
    assert isinstance(inputs, dict)
    #inputs = dict([(k, flatten_parameters(v)) for k,v in inputs.items()])

    log.info("Executing %s in %s with inputs %s", name, job_dir, inputs)
    desc_name = "{} with inputs {} ({})".format(name, inputs, job_dir)

    run_stmts = []
    for i, x in enumerate(rule.run_stmts):
        command, script_body = x
        command, script_body = expand_run(jinja2_env, command, script_body, config, inputs)
        if script_body != None:
            formatted_script_body = textwrap.dedent(script_body)
            script_name = os.path.abspath(os.path.join(job_dir, "script_%d"%i))
            with open(script_name, "w") as fd:
                fd.write(formatted_script_body)
            command += " "+script_name

        run_stmts.append(command)

    execution = exec_script(name,
                       id,
                       language,
                       job_dir,
                       run_stmts,
                       outputs, capture_output, prologue, desc_name)
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

            stdout_path = os.path.join(e.job_dir, "stdout.txt")
            stderr_path = os.path.join(e.job_dir, "stderr.txt")
            with open(os.path.join(e.job_dir, "description.txt")) as fd:
                desc_name = fd.read()

            ee = Execution(e.transform, e.id, e.job_dir, ProcStub(e.exec_xref), rule.outputs, (stdout_path, stderr_path), desc_name)
            executing.append(ee)
            log.warn("Reattaching existing job {}: {}".format(e.transform, e.exec_xref))
        else:
            log.warn("Canceling {}".format(e.id))
            j.cancel_execution(e.id)
    return executing

def get_job_dir(state_dir, job_id):
    working_dir = os.path.join(state_dir, "working")
    return working_dir + "/r" + str(job_id)

from . import xref
def main_loop(jinja2_env, j, new_object_listener, rules, state_dir, executing, max_concurrent_executions, capture_output, req_confirm):
    active_job_ids = set([e.id for e in executing])

    resolver = xref.Resolver(rules.vars)

    prev_msg = None
    abort = False
    while not abort:
        pending_jobs = j.get_pending()
        msg = "%d processes running, %d executions pending" % ( len(executing), len(pending_jobs) - len(executing) )
        if prev_msg != msg:
            log.info(msg)
        prev_msg = msg
        if len(executing) == 0 and len(pending_jobs) == 0:
            # now that we've completed everything, check for deferred jobs by marking them as ready.  If we have any, loop again
            j.enable_deferred()
            deferred_jobs = len(j.get_pending())
            if deferred_jobs > 0:
                log.info("Marked deferred %d executions as ready", deferred_jobs)
                continue
            break

        did_useful_work = False
        for job in pending_jobs:
            assert isinstance(job, dep.RuleExecution)

            # if we've hit our cap on concurrent executions, just bail before spawning anything new
            if len(executing) >= max_concurrent_executions:
                break

            # if this job is one we're currently running, just move along
            if job.id in active_job_ids:
                continue

            active_job_ids.add(job.id)
            did_useful_work = True

            rule = rules.get_rule(job.transform)
            inputs, xrefs_resolved = preprocess_inputs(j, resolver, job.inputs)
            if xrefs_resolved:
                log.info("Resolved xrefs on rule, new version will be executed next pass")
                continue

            # if we're required confirmation from the user, do this before we continue
            if req_confirm:
                while True:
                    answer = input("Proceed to run {} on {}? (y)es, (a)lways or (q)uit: ".format(job.transform, inputs))
                    if not (answer in ["y", "a", "q"]):
                        print("Invalid input")
                    break
                if answer == "a":
                    req_confirm = False
                elif answer == "q":
                    abort = True
                    break

            exec_id = j.record_started(job.id)

            job_dir = get_job_dir(state_dir, exec_id)
            if not os.path.exists(job_dir):
                os.makedirs(job_dir)

            e = execute(job.transform, resolver, jinja2_env, exec_id, job_dir, inputs, rule, rules.get_vars(), capture_output)
            executing.append(e)
            j.update_exec_xref(e.id, "PID:{}".format(e.proc.pid), job_dir)

        for i, e in reversed(list(enumerate(executing))):
            failure, completion = e.get_completion()

            if failure == None and completion == None:
                continue

            del executing[i]
            timestamp = datetime.datetime.now().isoformat()

            if failure != None:
                log.error("Task failed %s: %s", e.desc_name, failure)
                if e.captured_stdouts != None:
                    log_job_output(e.job_dir, e.captured_stdouts)
                j.record_completed(timestamp, e.id, dep.STATUS_FAILED, {})
            elif completion != None:
                j.record_completed(timestamp, e.id, dep.STATUS_COMPLETED, completion)

            did_useful_work = True
        
        if not did_useful_work:
            time.sleep(0.5)

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
    #stdout_path = os.path.relpath(os.path.join(job_dir, "stdout.txt"))
    #stderr_path = os.path.relpath(os.path.join(job_dir, "stderr.txt"))
    log.error("Dumping last {} lines of {}".format(line_count, stdout_path))
    _tail_file(stdout_path)
    log.error("Dumping last {} lines of {}".format(line_count, stderr_path))
    _tail_file(stderr_path)


def add_xref(j, xref):
    timestamp = datetime.datetime.now().isoformat()
    d = dict(xref.obj)
    d["$xref_url"] = xref.url
    return j.add_obj("public", timestamp, d, overwrite=False)

class Rules:
    def __init__(self):
        self.rule_by_name = {}
        self.vars = {}
        self.xrefs = []

    def add_xref(self, xref):
        self.xrefs.append(xref)

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
        self.xrefs.extend(other.xrefs)

    def __repr__(self):
        return "<Rules vars:{}, rules:{}>".format(self.vars, list(self))

def read_deps(filename, initial_vars={}):
    rules = Rules()
    for name, value in initial_vars.items():
        rules.set_var(name, value)

    p = parser.parse(filename)
    for dec in p:
        if isinstance(dec, parser.XRef):
            rules.add_xref(dec)
        elif isinstance(dec, parser.LetStatement):
            rules.set_var(dec.name, dec.value)
        elif isinstance(dec, parser.IncludeStatement):
            child_rules = read_deps(dec.filename)
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

def dot_cmd(state_dir, detailed):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    print(j.to_dot(detailed))

def list_cmd(state_dir):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    j.dump()

def debugrun(state_dir, depfile, target, override_vars):
    jinja2_env = create_jinja2_env()

    db_path = os.path.join(state_dir, "db.sqlite3")
    print("opening", db_path)
    j = dep.open_job_db(db_path)

    rules = read_deps(depfile)

    for var, value in override_vars.items():
        rules.set_var(var, value)

    rule = rules.get_rule(target)
    queries, predicates = convert_input_spec_to_queries(jinja2_env, rule, rules.vars)
    for q in queries:
        t = dep.Template([q], [], rule.name)
        applications = j.query_template(t)
        log.info("{} matches for {}".format(len(applications), q))

    applications = j.query_template(dep.Template(queries, predicates, rule.name))
    log.info("{} matches for entire rule".format(len(applications), q))

def expand_run(jinja2_env, command, script_body, config, inputs):
    command = render_template(jinja2_env, command, config, inputs=inputs)
    if script_body != None:
        script_body = render_template(jinja2_env, script_body, config, inputs=inputs)
    return (command, script_body)

def expand_dict(jinja2_env, d, config, **kwargs):
    assert isinstance(d, dict)
    assert isinstance(config, dict)

    new_output = {}
    for k, v in d.items():
#        print("expanding k", k)
        k = render_template(jinja2_env, k, config, **kwargs)
        # QueryVariables get introduced via expand input spec
        if not isinstance(v, parser.QueryVariable):
            if isinstance(v, dict):
                v = expand_dict(jinja2_env, v, config, **kwargs)
            else:
                v = render_template(jinja2_env, v, config, **kwargs)
        new_output[k] = v

    return new_output

def expand_outputs(jinja2_env, output, config, **kwargs):
    return expand_dict(jinja2_env, output, config, **kwargs)

def expand_input_spec(jinja2_env, spec, config):
    return expand_dict(jinja2_env, spec, config)
    # assert isinstance(config, dict)
    # return parser.InputSpec(
    #     render_template(jinja2_env, spec.variable, config),
    #     expand_dict(jinja2_env, spec.json_obj, config)
    # )

def expand_xref(jinja2_env, xref, config):
    return parser.XRef(
        render_template(jinja2_env, xref.url, config),
        expand_dict(jinja2_env, xref.obj, config)
    )

def convert_input_spec_to_queries(jinja2_env, rule, config):
    queries = []
    predicates = []
    pairs_by_var = collections.defaultdict(lambda: [])
    for bound_name, spec, for_all in rule.inputs:
        assert bound_name != ""
        spec = expand_input_spec(jinja2_env, spec, config)

        constants = {}
        for prop_name, value in spec.items():
            if isinstance(value, parser.QueryVariable):
                pairs_by_var[value.name].append( (bound_name, prop_name) )
            else:
                constants[prop_name] = value
        if for_all:
            q = dep.ForAll(bound_name, constants)
        else:
            q = dep.ForEach(bound_name, constants)

        queries.append(q)

    for var, pairs in pairs_by_var.items():
        predicates.append(dep.PropsMatch(pairs))

    return queries, predicates

def to_template(jinja2_env, rule, config):
    queries, predicates = convert_input_spec_to_queries(jinja2_env, rule, config)
    return dep.Template(queries, predicates, rule.name)

def quote_str(x):
    if isinstance(x, jinja2.StrictUndefined):
        return x
    else:
        return json.dumps(x)

def create_jinja2_env():
    jinja2_env = jinja2.Environment(undefined=jinja2.StrictUndefined)

    jinja2_env.filters['quoted'] = quote_str
    return jinja2_env

def print_rules(depfile):
    rules = read_deps(depfile)
    for rule in rules:
        assert (isinstance(rule, parser.Rule))
        print(rule.name)

def gc(state_dir):
    db_path = os.path.join(state_dir, "db.sqlite3")
    j = dep.open_job_db(db_path)

    def rm_job_dir(job_id):
        job_dir = get_job_dir(state_dir, job_id)
        if os.path.exists(job_dir):
            log.warn("Removing unused directory: %s", job_dir)
            shutil.rmtree(job_dir)

    j.gc(rm_job_dir)

def main(depfile, state_dir, forced_targets, override_vars, max_concurrent_executions, capture_output, req_confirm):
    jinja2_env = create_jinja2_env()

    if not os.path.exists(state_dir):
        os.makedirs(state_dir)

    working_dir = os.path.join(state_dir, "working")
    if not os.path.exists(working_dir):
        os.makedirs(working_dir)
    dlcache = os.path.join(state_dir, 'dlcache')
    if not os.path.exists(dlcache):
        os.makedirs(dlcache)
    db_path = os.path.join(state_dir, "db.sqlite3")
    j = dep.open_job_db(db_path)

    # handle case where we explicitly state some templates to execute.  Make sure nothing else executes
    if len(forced_targets) > 0:
        j.limitStartToTemplates(forced_targets)
        for target in forced_targets:
            count = j.invalidate_rule_execution(target)
            log.info("Cleared %d old executions of %s", count, target)

    script_dir = os.path.dirname(os.path.abspath(depfile))

    rules = read_deps(depfile, dict(DL_CACHE_DIR=dlcache,
                                    SCRIPT_DIR=script_dir,
                                    PROLOGUE=""))

    for var, value in override_vars.items():
        rules.set_var(var, value)

    for xref in rules.xrefs:
        add_xref(j, expand_xref(jinja2_env, xref, rules.vars))

    executing = reattach(j, rules)

    for dec in rules:
        assert (isinstance(dec, parser.Rule))
        j.add_template(to_template(jinja2_env, dec, rules.vars))

    def new_object_listener(obj):
        timestamp = datetime.datetime.now().isoformat()
        j.add_obj(timestamp, obj)
    try:
        main_loop(jinja2_env, j, new_object_listener, rules, state_dir, executing, max_concurrent_executions, capture_output, req_confirm)
    except FatalUserError as e:
        print("Error: {}".format(e))



