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

from conseq import dep
from conseq import parser
import six

from conseq import exec_client

log = logging.getLogger(__name__)

class FatalUserError(Exception):
    pass

class JobFailedError(FatalUserError):
    pass

class LazyConfig:
    def __init__(self, render_template, config_dict):
        self._config_dict = config_dict
        self._render_template = render_template

    def __getitem__(self, name):
        v = self._config_dict[name]
        return self._render_template(v)

class MissingTemplateVar(Exception):
    def __init__(self, message, variables, template):
        super(MissingTemplateVar, self).__init__()
        self.variables = variables
        self.template = template
        self.message = message

    def get_error(self):
        var_defs = []
        for k, v in self.variables.items():
            if isinstance(v, dict):
                var_defs.append("  {}:".format(repr(k)))
                for k2, v2 in v.items():
                    var_defs.append("    {}: {}".format(repr(k2), repr(v2)))
            else:
                var_defs.append("  {}: {}".format(repr(k), repr(v)))

        var_block = "".join(x+"\n" for x in var_defs)
        return ("Template error: {}, applying vars:\n{}\n to template:\n{}".format(self.message, var_block, self.template))

def render_template(jinja2_env, template_text, config, **kwargs):
    assert isinstance(template_text, six.string_types), "Expected string for template but got {}".format(repr(template_text))
    kwargs = dict(kwargs)

    def render_template_callback(text):
        try:
            rendered = jinja2_env.from_string(text).render(**kwargs)
            return rendered
        except jinja2.exceptions.UndefinedError as ex:
            raise MissingTemplateVar(ex.message, kwargs, text)

    kwargs["config"] = LazyConfig(render_template_callback, config)

    return render_template_callback(template_text)

def generate_run_stmts(job_dir, command_and_bodies, jinja2_env, config, inputs, resolver_state):
    run_stmts = []
    for i, x in enumerate(command_and_bodies):
        exec_profile, command, script_body = x
        assert exec_profile == "default"
        command, script_body = expand_run(jinja2_env, command, script_body, config, inputs)
        if script_body != None:
            formatted_script_body = textwrap.dedent(script_body)
            script_name = os.path.abspath(os.path.join(job_dir, "script_%d"%i))
            with open(script_name, "w") as fd:
                fd.write(formatted_script_body)
            command += " "+os.path.relpath(script_name, job_dir)
            resolver_state.add_script(script_name)

        run_stmts.append(command)
    return run_stmts

def format_inputs(inputs):
    lines = []

    def append_kv(v):
        for prop, prop_value in v.items():
            lines.append("     {}: {}\n".format(prop, repr(prop_value)))

    for k, v in inputs.items():
        if isinstance(v, list):
            for vi, ve in enumerate(v):
                lines.append("  {}[{}]:\n".format(k, vi))
                append_kv(ve)
        else:
            lines.append("  {}:\n".format(k))
            append_kv(v)

    return "".join(lines)

def execute(name, resolver, jinja2_env, id, job_dir, inputs, rule, config, capture_output, resolver_state, client):
    try:
        prologue = render_template(jinja2_env, config["PROLOGUE"], config)

        if rule.outputs == None:
            outputs = None
        else:
            outputs = [expand_outputs(jinja2_env, output, config, inputs=inputs) for output in rule.outputs]
        assert isinstance(inputs, dict)

        log.info("Executing %s in %s with inputs:\n%s", name, job_dir, format_inputs(inputs))
        desc_name = "{} with inputs {} ({})".format(name, inputs, job_dir)

        if len(rule.run_stmts) > 0:
            flock_stmt = get_flock_statement(rule)
            if flock_stmt is not None:
                execution = client.execute(id, None, flock_stmt.fn_prefix, flock_stmt.scripts, job_dir)
            else:
                run_stmts = generate_run_stmts(job_dir, rule.run_stmts, jinja2_env, config, inputs, resolver_state)

                execution = client.exec_script(name,
                                   id,
                                   job_dir,
                                   run_stmts,
                                   outputs, capture_output, prologue, desc_name, resolver_state)
        else:
            # fast path when there's no need to spawn an external process.  (mostly used by tests)
            assert outputs != None, "No body, nor outputs specified.  This rule does nothing"
            execution = exec_client.SuccessfulExecutionStub(id, outputs)

        return execution

    except MissingTemplateVar as ex:
        return exec_client.FailedExecutionStub(id, ex.get_error())

def reattach(j, rules):
    pending_jobs = j.get_started_executions()
    if len(pending_jobs) > 0:
        log.warn("Reattaching jobs that were started in a previous invocation of conseq, but had not terminated before conseq exited: %s", pending_jobs)
    executing = []
    for e in pending_jobs:
        if e.exec_xref != None:
            rule = rules.get_rule(e.transform)
            client = rules.get_client(rule.executor)
            ee = client.reattach(e.exec_xref)
            executing.append(ee)
            log.warn("Reattaching existing job {}: {}".format(e.transform, e.exec_xref))
        else:
            log.warn("Canceling {}".format(e.id))
            j.cancel_execution(e.id)
    return executing

def get_job_dir(state_dir, job_id):
    return os.path.join(state_dir, "r" + str(job_id))

def confirm_execution(transform, inputs):
    while True:
        answer = input("Proceed to run {} on {}? (y)es, (a)lways or (q)uit: ".format(transform, inputs))
        if not (answer in ["y", "a", "q"]):
            print("Invalid input")
        return answer

def get_execution_summary(executing):
    counts = collections.defaultdict(lambda: 0)
    for e in executing:
        counts[e.get_state_label()] += 1
    keys = list(counts.keys())
    keys.sort()
    return ", ".join(["%s:%d"%(k, counts[k]) for k in keys])

import contextlib
import signal
@contextlib.contextmanager
def capture_sigint():
    interrupted = [False]

    original_sigint = signal.getsignal(signal.SIGINT)

    def set_interrupted(signum, frame):
        signal.signal(signal.SIGINT, original_sigint)
        interrupted[0] = True
        log.warn("Interrupted!")

    signal.signal(signal.SIGINT, set_interrupted)

    yield lambda: interrupted[0]

    signal.signal(signal.SIGINT, original_sigint)

def ask_user_to_cancel(j, executing):
    while True:
        answer = input("Terminate {} running before exiting (y/n)? ".format(len(executing)))
        if (answer in ["y", "n"]):
            break
        print("Invalid input")

    if answer == 'y':
        for e in executing:
            e.cancel()
        #TODO: I think this might be here as an unfinished change.  We need to mark the jobs that were running
        # as no longer running so that we don't attempt to re-attach them
        #j.cleanup_incomplete()

from conseq import xref
def main_loop(jinja2_env, j, new_object_listener, rules, state_dir, executing, max_concurrent_executions, capture_output, req_confirm, maxfail):
    active_job_ids = set([e.id for e in executing])

    resolver = xref.Resolver(rules.vars)

    prev_msg = None
    abort = False
    interrupted = False
    failure_count = 0
    with capture_sigint() as was_interrupted_fn:
        while not abort:
            interrupted = was_interrupted_fn()
            if interrupted:
                break

            if failure_count >= maxfail:
                break

            pending_jobs = j.get_pending()
            summary = get_execution_summary(executing)
            msg = "%d processes running (%s), %d executions pending" % ( len(executing), summary, len(pending_jobs) )
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

                # process xrefs which might require rewriting an artifact
                xrefs_resolved = exec_client.preprocess_xref_inputs(j, resolver, job.inputs)
                if xrefs_resolved:
                    log.info("Resolved xrefs on rule, new version will be executed next pass")
                    continue

                # localize paths that will be used in scripts
                client = rules.get_client(rule.executor)
                inputs, resolver_state = client.preprocess_inputs(resolver, job.inputs)

                # if we're required confirmation from the user, do this before we continue
                if req_confirm:
                    answer = confirm_execution(job.transform, inputs)
                    if answer == "a":
                        req_confirm = False
                    elif answer == "q":
                        abort = True
                        break

                # maybe record_started and update_exec_xref should be merged so anything started
                # always has an xref
                exec_id = j.record_started(job.id)

                job_dir = get_job_dir(state_dir, exec_id)
                if not os.path.exists(job_dir):
                    os.makedirs(job_dir)

                e = execute(job.transform, resolver, jinja2_env, exec_id, job_dir, inputs, rule, rules.get_vars(), capture_output, resolver_state, client)
                executing.append(e)
                #print("updating exec {} with {}".format(e.id, e.get_external_id()))
                j.update_exec_xref(e.id, e.get_external_id(), job_dir)

            for i, e in reversed(list(enumerate(executing))):
                failure, completion = e.get_completion()

                if failure == None and completion == None:
                    continue

                del executing[i]
                timestamp = datetime.datetime.now().isoformat()

                if failure != None:
                    j.record_completed(timestamp, e.id, dep.STATUS_FAILED, {})
                    failure_count += 1
                elif completion != None:
                    j.record_completed(timestamp, e.id, dep.STATUS_COMPLETED, completion)

                did_useful_work = True

            if not did_useful_work:
                time.sleep(0.5)

    # interrupted and
    if len(executing) > 0:
        ask_user_to_cancel(j, executing)

def _datetimefromiso(isostr):
    return datetime.datetime.strptime(isostr,"%Y-%m-%dT%H:%M:%S.%f")

def add_artifact_if_missing(j, obj):
    timestamp = datetime.datetime.now()
    d = dict(obj)
    return j.add_obj(dep.DEFAULT_SPACE, timestamp.isoformat(), d, overwrite=False)

def add_xref(j, xref, refresh):
    timestamp = datetime.datetime.now()
    d = dict(xref.obj)
    d["$xref_url"] = xref.url
    overwrite = False
    if refresh:
        existing = j.find_objs(dep.DEFAULT_SPACE, d)
        if len(existing) > 0:
            if len(existing) > 1:
                raise Exception("Looking for xref {} resulted in multiple matches: {}".format(d, existing))
            existing = existing[0]
            # TODO: fix this to work with all xref types
            if os.path.exists(xref.url):
                file_mtime = datetime.datetime.fromtimestamp(os.path.getmtime(xref.url))
                if file_mtime > _datetimefromiso(existing.timestamp):
                    log.info("Xref %s has been updated", xref.url)
                    overwrite = True

    return j.add_obj(dep.DEFAULT_SPACE, timestamp.isoformat(), d, overwrite=overwrite)

class Rules:
    def __init__(self):
        self.rule_by_name = {}
        self.vars = {}
        self.xrefs = []
        self.objs = []
        self.types = {}
        self.exec_clients = {"default": exec_client.LocalExecClient()}

    def add_xref(self, xref):
        self.xrefs.append(xref)

    def add_if_missing(self, obj):
        self.objs.append(obj)

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

    def add_client(self, name, client):
        self.exec_clients[name] = client

    def get_client(self, name):
        return self.exec_clients[name]

    def add_type(self, typedef):
        name = typedef.name
        if name in self.types:
            raise Exception("Duplicate type for {}".format(name))
        self.types[name] = typedef

    def merge(self, other):
        for name, rule in other.rule_by_name.items():
            self.set_rule(name, rule)
        self.vars.update(other.vars)
        self.xrefs.extend(other.xrefs)
        self.objs.extend(other.objs)
        self.exec_clients.update(other.exec_clients)

        for t in other.types.values():
            self.types.add_type(t)

    def __repr__(self):
        return "<Rules vars:{}, rules:{}>".format(self.vars, list(self))

def get_flock_statement(rule):
    "Returns None if this rule has no flock statements.  Otherwise returns reference to it"
    flock_stmts = [x for x in rule.run_stmts if type(x) == parser.FlockStmt]
    if len(flock_stmts) > 0:
        assert len(flock_stmts) == 1, "If a flock job is specified, no other run statments can be given"
        return flock_stmts[0]
    return None

def read_deps(filename, initial_vars={}):
    rules = Rules()
    for name, value in initial_vars.items():
        rules.set_var(name, value)

    p = parser.parse(filename)

    for dec in p:
        if isinstance(dec, parser.LetStatement):
            rules.set_var(dec.name, dec.value)

    for dec in p:
        if isinstance(dec, parser.XRef):
            rules.add_xref(dec)
        elif isinstance(dec, parser.AddIfMissingStatement):
            rules.add_if_missing(dec.json_obj)
        elif isinstance(dec, parser.LetStatement):
            # these were handled above
            pass
        elif isinstance(dec, parser.IncludeStatement):
            child_rules = read_deps(os.path.expanduser(dec.filename))
            rules.merge(child_rules)
        elif isinstance(dec, parser.TypeDefStmt):
            rules.add_type(dec)
        elif isinstance(dec, parser.ExecProfileStmt):
            client = exec_client.create_client(dec.name, dec.properties)
            rules.add_exec_client(dec.name, client)
        else:
            assert isinstance(dec, parser.Rule)
            rules.set_rule(dec.name, dec)
    return rules

def ls_cmd(state_dir, space, predicates, groupby, columns):
    from tabulate import tabulate
    from conseq import depquery

    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    if space is None:
        space = j.get_current_space()
    subset = j.find_objs(space, dict(predicates))
    subset = [o.props for o in subset]

    def indent_str(s, depth):
        pad = " "*depth
        return "\n".join([pad + x for x in s.split("\n")])

    def print_table(subset, indent):
        if len(subset) > 1 and columns == None:
            counts = depquery.count_unique_values_per_property(subset)
            common_keys, variable_keys = depquery.split_props_by_counts(counts)
            common_table = [ [subset[0][k] for k in common_keys] ]
            if len(common_keys) > 0:
                print(indent_str("Properties shared by all {} rows:".format(len(subset)), indent))
                print(indent_str(tabulate(common_table, common_keys, tablefmt="simple"), indent+2))

        elif columns != None:
            variable_keys = columns
        else:
            # remaining case: columns == None and len(subset) == 1
            variable_keys = list(subset[0].keys())

        variable_table = []
        for row in subset:
            variable_table.append( [row.get(k) for k in variable_keys] )
        print(indent_str(tabulate(variable_table, variable_keys, tablefmt="simple"), indent))

    if groupby == None:
        print_table(subset, 0)
    else:
        by_pred = collections.defaultdict(lambda: [])
        for row in subset:
            by_pred[row.get(groupby)].append(row)

        for group, rows in by_pred.items():
            print("For {}={}:".format(groupby, group))
            print_table(rows, 2)
            print()

def rm_cmd(state_dir, dry_run, space, query, with_invalidate):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    if space is None:
        space = j.get_current_space()
    for o in j.find_objs(space, query):
        print("rm", o)
        if not dry_run:
            j.remove_obj(o.id, with_invalidate)

def dot_cmd(state_dir, detailed):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    print(j.to_dot(detailed))

def list_cmd(state_dir):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    j.dump()

def debugrun(state_dir, depfile, target, override_vars, config_file):
    jinja2_env = create_jinja2_env()

    db_path = os.path.join(state_dir, "db.sqlite3")
    print("opening", db_path)
    j = dep.open_job_db(db_path)

    initial_config = load_config(config_file)
    rules = read_deps(depfile, initial_vars=initial_config)

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
    spec = dict(spec)
    regexps = {}
    for k, v in spec.items():
        # if the value is a regexp, don't expand
        if not isinstance(v, six.string_types):
            regexps[k] = v
    for k in regexps.keys():
        del spec[k]

    expanded = expand_dict(jinja2_env, spec, config)
    for k, v in regexps.items():
        expanded[k] = v
    return expanded

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

def load_config(config_file):
    config = {}

    p = parser.parse(os.path.expanduser(config_file))
    for dec in p:
        if isinstance(dec, parser.LetStatement):
            config[dec.name] = dec.value
        else:
            raise Exception("Initial config is only allowed to use 'let' statements but encountered {}".format(dec))

    return config

def select_space(state_dir, name, create_if_missing):
    db_path = os.path.join(state_dir, "db.sqlite3")
    j = dep.open_job_db(db_path)
    j.select_space(name, create_if_missing)

def print_spaces(state_dir):
    db_path = os.path.join(state_dir, "db.sqlite3")
    j = dep.open_job_db(db_path)
    current_space = j.get_current_space()
    for space in j.get_spaces():
        selected = "*" if current_space == space else " "
        print("{} {}".format(selected, space))

def main(depfile, state_dir, forced_targets, override_vars, max_concurrent_executions, capture_output, req_confirm, config_file,
         refresh_xrefs=False, maxfail=1):
    jinja2_env = create_jinja2_env()

    if not os.path.exists(state_dir):
        os.makedirs(state_dir)

    dlcache = os.path.join(state_dir, 'dlcache')
    if not os.path.exists(dlcache):
        os.makedirs(dlcache)
    db_path = os.path.join(state_dir, "db.sqlite3")
    j = dep.open_job_db(db_path)

    # handle case where we explicitly state some templates to execute.  Make sure nothing else executes
    if len(forced_targets) > 0:
        j.limitStartToTemplates(forced_targets)
        for target in forced_targets:
            j.invalidate_rule_execution(target)
            log.info("Cleared old executions of %s", target)

    script_dir = os.path.dirname(os.path.abspath(depfile))

    initial_config = dict(DL_CACHE_DIR=dlcache,
                          SCRIPT_DIR=script_dir,
                          PROLOGUE="",
                          WORKING_DIR=state_dir)
    if config_file is not None:
        initial_config.update(load_config(config_file))

    rules = read_deps(depfile, initial_vars=initial_config)

    for var, value in override_vars.items():
        rules.set_var(var, value)

    for xref in rules.xrefs:
        add_xref(j, expand_xref(jinja2_env, xref, rules.vars), refresh_xrefs)

    for obj in rules.objs:
        add_artifact_if_missing(j, obj)

    executing = reattach(j, rules)

    # any jobs killed or other failures need to be removed so we'll attempt to re-run them
    j.cleanup_failed()

    for dec in rules:
        assert (isinstance(dec, parser.Rule))
        try:
            j.add_template(to_template(jinja2_env, dec, rules.vars))
        except MissingTemplateVar as ex:
            log.error("Could not load rule {}: {}".format(dec.name, ex.get_error()))
            return -1

    def new_object_listener(obj):
        timestamp = datetime.datetime.now().isoformat()
        j.add_obj(timestamp, obj)
    try:
        main_loop(jinja2_env, j, new_object_listener, rules, state_dir, executing, max_concurrent_executions, capture_output, req_confirm, maxfail)
    except FatalUserError as e:
        print("Error: {}".format(e))
        return -1

    return 0



