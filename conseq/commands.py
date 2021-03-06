import collections
import json
import logging
import os
import shutil
from io import StringIO

from conseq import dep
from conseq import helper
from conseq import xref
from conseq.config import read_rules
from conseq.dep import Obj, DEFAULT_SPACE
from conseq.depexec import convert_input_spec_to_queries, get_job_dir, remove_obj_and_children
from conseq.parser import ExpectKeyIs
from conseq.util import indent_str

log = logging.getLogger(__name__)


def print_rules(state_dir, depfile, config_file):
    rules = read_rules(state_dir, depfile, config_file)
    names = [rule.name for rule in rules]
    names.sort()
    for name in names:
        print(name)


def print_history(state_dir):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    for exec_ in j.get_all_executions():

        lines = []
        lines.append("  inputs:")
        for name, value in exec_.inputs:
            if isinstance(value, dep.Obj):
                value = [value]
            lines.append("    {}:".format(name))
            for _value in value:
                for k, v in _value.props.items():
                    lines.append("      {}: {}".format(k, v))

        if len(exec_.outputs) > 0:
            lines.append("  outputs:")
            for value in exec_.outputs:
                for k, v in value.props.items():
                    lines.append("    {}: {}".format(k, v))

        print("rule {}: (execution id: {}, status: {})".format(
            exec_.transform, exec_.id, exec_.status))
        for line in lines:
            print(line)

        print("")


def localize_cmd(state_dir, space, predicates, depfile, config_file):
    rules = read_rules(state_dir, depfile, config_file)

    resolver = xref.Resolver(state_dir, rules.vars)

    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    if space is None:
        space = j.get_current_space()
    subset = j.find_objs(space, dict(predicates))
    for obj in subset:
        for k, v in obj.props.items():
            if isinstance(v, dict) and "$file_url" in v:
                url = v["$file_url"]
                r = resolver.resolve(url)
                log.info("resolved %s to %s", url, r)


def _print_execution(execution):
    print("Executed {} (id={}, state={}, dir={}):".format(repr(execution.transform), execution.id, execution.status, execution.job_dir))
    if len(execution.inputs) > 0:
        print("  inputs:")
        for name, artifact in execution.inputs:
            print("   {} = {}".format(name, artifact))
    if len(execution.outputs) > 0:
        print("  outputs:")
        for artifact in execution.outputs:
            print("   {}".format(artifact))
    print()


def lsexec(state_dir):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    executions = j.get_all_executions()
    for execution in executions:
        _print_execution(execution)


def downstream_cmd(state_dir, space, predicates):

    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    if space is None:
        space = j.get_current_space()

    from collections import defaultdict
    rules_by_obj_id = defaultdict(lambda: set())

    all_rules = j.get_all_executions()
    for rule in all_rules:
        if rule.status == "canceled":
            continue

        for name, value in rule.inputs:
            if not isinstance(value, tuple):
                value = [value]
            for v in value:
                rules_by_obj_id[v.id].add(rule.transform)

    #print(rules_by_obj_id)

    subset = j.find_objs(space, dict(predicates))
    for o in subset:
        print(f"artifact {o} has the following downstream:")
        downstreams = j.find_all_reachable_downstream_objs([o.id])
        for downstream in downstreams:
            rules = rules_by_obj_id[downstream.id]
            downstream_id = downstream.id
            print(f"  {downstream_id}: rules {rules}")
        print("")
    # subset is list of key -> value pairs


def ls_cmd(state_dir, space, predicates, groupby, columns):
    from tabulate import tabulate
    from conseq import depquery

    cache_db = xref.open_cache_db(state_dir)

    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    if space is None:
        space = j.get_current_space()
    subset = j.find_objs(space, dict(predicates))
    subset = [o.props for o in subset]

    def print_table(subset, indent):
        if len(subset) > 1 and columns == None:
            counts = depquery.count_unique_values_per_property(subset)
            common_keys, variable_keys = depquery.split_props_by_counts(counts)
            common_table = [[subset[0][k] for k in common_keys]]
            if len(common_keys) > 0:
                print(indent_str(
                    "Properties shared by all {} rows:".format(len(subset)), indent))
                print(indent_str(tabulate(common_table,
                                          common_keys, tablefmt="simple"), indent + 2))

        elif columns != None:
            variable_keys = columns
        else:
            # remaining case: columns == None and len(subset) == 1
            variable_keys = list(subset[0].keys())

        variable_table = []
        for row in subset:
            full_row = []
            for k in variable_keys:
                v = row.get(k)
                if isinstance(v, dict) and "$file_url" in v:
                    cache_rec = cache_db.get(v["$file_url"])
                    if cache_rec is not None:
                        v = {"$filename": cache_rec[0]}
                full_row.append(str(v))
            variable_table.append(full_row)
        print(indent_str(tabulate(variable_table,
                                  variable_keys, tablefmt="simple"), indent))

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


def rm_cmd(state_dir, dry_run, space, query):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    if space is None:
        space = j.get_current_space()

    root_objs = j.find_objs(space, query)
    root_obj_ids = [o.id for o in root_objs]

    remove_obj_and_children(j, root_obj_ids, dry_run)


def dot_cmd(state_dir, detailed):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    print(j.to_dot(detailed))


def list_cmd(state_dir):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    j.dump()


def export_cmd(state_dir, depfile, config_file, dest_s3_path):
    out = StringIO()

    rules = read_rules(state_dir, depfile, config_file)
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))

    objs = j.find_objs(DEFAULT_SPACE, {})
    print(len(objs))
    vars = rules.vars

    cas_remote = helper.Remote(vars["S3_STAGING_URL"], '.', vars['AWS_ACCESS_KEY_ID'],
                               vars['AWS_SECRET_ACCESS_KEY'])

    def process_value(value):
        if isinstance(value, dict):
            if '$filename' in value:
                url = cas_remote.upload_to_cas(value['$filename'])
                value = {"$file_url": url}
        return value

    def process_filenames(obj: Obj):
        translated = {}
        for key, value in obj.props.items():
            if isinstance(value, list) or isinstance(value, tuple):
                value = [process_value(x) for x in value]
            else:
                value = process_value(value)
            translated[key] = value

        if "$manually-added" not in translated:
            translated["$manually-added"] = {'$value': 'false'}

        return translated

    def reindent(s, ident):
        indent_str = " " * ident
        lines = s.split("\n")

        return "\n".join([lines[0]] + [indent_str + x for x in lines[1:]])

    for obj in objs:
        props = process_filenames(obj)
        out.write("add-if-missing {}\n\n".format(reindent(json.dumps(props), 3)))

    def get_key_props(obj):
        props = {}
        for key, value in obj.props.items():
            if isinstance(value, dict) and (("$filename" in value) or ("$file_url" in value) or ("$value" in value)):
                continue
            props[key] = value
        return props

    def value_as_json(value):
        if isinstance(value, tuple):
            return json.dumps([get_key_props(x) for x in value], indent=3)
        else:
            return json.dumps(get_key_props(value), indent=3)

    executions = j.get_all_executions()
    for execution in executions:
        # if execution.status == "complete":
        out.write(
            "remember-executed transform : \"{}\"\n".format(execution.transform))
        for input in execution.inputs:
            out.write("   input \"{}\" : {}\n".format(
                input[0], reindent(value_as_json(input[1]), 3)))
        for output in execution.outputs:
            out.write("   output : {}\n".format(
                reindent(value_as_json(output), 3)))
        out.write("\n")

    log.info("Uploading artifact metadata to %s", dest_s3_path)
    cas_remote.upload_str(dest_s3_path, out.getvalue())


def debugrun(state_dir, depfile, target, override_vars, config_file):
    db_path = os.path.join(state_dir, "db.sqlite3")
    print("opening", db_path)
    j = dep.open_job_db(db_path)

    rules = read_rules(state_dir, depfile, config_file)

    for var, value in override_vars.items():
        rules.set_var(var, value)

    rule = rules.get_rule(target)
    queries, predicates = convert_input_spec_to_queries(
        rules.jinja2_env, rule, rules.vars)
    for q in queries:
        t = dep.Template([q], [], rule.name)
        applications = j.query_template(t)
        log.info("{} matches for {}".format(len(applications), q))

    applications = j.query_template(
        dep.Template(queries, predicates, rule.name))
    log.info("{} matches for entire rule".format(len(applications)))


def gc(state_dir):
    if not os.path.exists(state_dir):
        log.warning("Nothing to do (No such directory: {})".format(state_dir))
        return

    db_path = os.path.join(state_dir, "db.sqlite3")

    j = dep.open_job_db(db_path)

    def rm_job_dir(job_id):
        job_dir = get_job_dir(state_dir, job_id)
        if os.path.exists(job_dir):
            log.warning("Removing unused directory: %s", job_dir)
            shutil.rmtree(job_dir)

    j.gc(rm_job_dir)


def _rules_to_dot(rules):
    """
    :return: a graphviz graph in dot syntax approximating the execution DAG
    """
    stmts = []
    objs = {}
    rule_nodes = {}

    def add_obj(type):
        if type in objs:
            return objs[type]['id']
        id = len(objs)
        objs[type] = dict(id=id, type=type)
        return id

    def add_rule(rule_name, filename):
        if rule_name in rule_nodes:
            return rule_nodes[rule_name]['id']
        id = len(rule_nodes)
        rule_nodes[rule_name] = dict(id=id, name=rule_name, filename=filename)
        return id

    for rule in rules:
        rule_id = add_rule(rule.name, rule.filename)
        for input in rule.inputs:
            # print(input)
            obj_id = add_obj(input.json_obj.get("type", "unknown"))

            #            stmts.append("o{} -> r{} [label=\"{}\"]".format(obj_id, rule_id, input.variable))
            stmts.append("o{} -> r{}".format(obj_id, rule_id))

        outputs = []
        if rule.outputs is not None:
            outputs.extend(rule.outputs)

        for expectation in rule.output_expectations:
            const_key_vals = {}
            for predicate in expectation.predicates:
                if isinstance(predicate, ExpectKeyIs):
                    const_key_vals[predicate.key] = predicate.value
            outputs.append(const_key_vals)

        for output in outputs:
            obj_id = add_obj(output.get("type", "unknown"))
            stmts.append("r{} -> o{}".format(rule_id, obj_id))

    for node in rule_nodes.values():
        stmts.append(
            "r{} [shape=box, style=\"filled\", fillcolor=\"gray\", label=\"{}\n{}\"]".format(node['id'], node['name'],
                                                                                             node['filename']))

    for obj in objs.values():
        prop_values = ["type=" + obj['type']]
        label = "\\n".join(prop_values)
        stmts.append("o{} [label=\"{}\"]".format(obj['id'], label))

    return "digraph { " + (";\n".join(set(stmts))) + " } "


def alt_dot(state_dir, depfile, config_file):
    rules = read_rules(state_dir, depfile, config_file)
    print(_rules_to_dot(rules))


def superdot(state_dir, depfile, config_file):
    from .scheduler import construct_graph, graph_to_dot

    rules = read_rules(state_dir, depfile, config_file)
    g = construct_graph(rules)

    with open("dump.dot", "w") as fd:
        fd.write(graph_to_dot(g))
