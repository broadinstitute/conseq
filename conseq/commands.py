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
from conseq.depexec import (
    convert_input_spec_to_queries,
    get_job_dir,
    remove_obj_and_children,
)
from conseq.parser import ExpectKeyIs
from conseq.util import indent_str
import re

log = logging.getLogger(__name__)


def print_rules(state_dir, depfile, config_file, mode, rule_name):
    rules = read_rules(state_dir, depfile, config_file)
    if mode == "all":
        names = [rule.name for rule in rules]
    elif mode == "up":
        raise NotImplemented()
    elif mode == "down":
        raise NotImplemented()
    else:
        raise Exception(f"Expected {mode} to be all, up or down")
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

        print(
            "rule {}: (execution id: {}, status: {})".format(
                exec_.transform, exec_.id, exec_.status
            )
        )
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
    print(
        "Executed {} (id={}, state={}, dir={}):".format(
            repr(execution.transform), execution.id, execution.status, execution.job_dir
        )
    )
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


def stage_cmd(export_file, conseq_file, dest_dir):
    from conseq import depexec, exec_client
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"Populating temp repo at {tmpdir}")
        # First import the export into a temp database
        db_path = os.path.join(tmpdir, "db.sqlite3")
        j = dep.open_job_db(db_path)

        export_contents = read_rules(dest_dir, export_file, config_file=None)

        # process add-if-missing statements
        depexec.reconcile_db(
            j,
            export_contents.jinja2_env,
            export_contents.get_rule_specifications(),
            export_contents.objs,
            export_contents.vars
        )

        # handle the remember-executed statements
        with j.transaction():
            for exec_ in export_contents.remember_executed:
                j.remember_executed(exec_)

        # now try to apply the rules in the conseq file provided to find input artifacts

        rules = read_rules(dest_dir, conseq_file, config_file=None)
        resolver = xref.Resolver(dest_dir, rules.vars)

        applications = []
        for rule_name in rules.rule_by_name.keys():
            rule = rules.get_rule(rule_name)
            queries, predicates = convert_input_spec_to_queries(
                rules.jinja2_env, rule, rules.vars
            )
            applications.extend(j.query_template(dep.Template(queries, predicates, rule.name)))
        print("found", applications)
        breakpoint()

        artifact_ids_used_as_inputs = set()

        for application in applications:
            space, bindings, rule_name = application
            for bound_name, bound_artifacts in bindings:
                # if we have a single artifact (as opposed to multiple) turn it into a list so
                # that bound_artifacts is always a list
                if isinstance(bound_artifacts, Obj):
                    bound_artifacts = [bound_artifacts]
                
                for bound_artifact in bound_artifacts:
                    artifact_ids_used_as_inputs.add(bound_artifact.id)
                
        # now we've got a set (deduplicated) artifact_ids that were used by all of those
        # rules. Now, some of those artifacts might be outputs of other rules in this same file
        # so, we'd like to exclude all the artifact ids which are downstream of all the rules in this 
        # conseq file.
        downstream_object_ids = set()
        for transform in rules.rule_by_name.keys():
            obj_ids = j.find_rule_output_ids(transform)
            downstream_object_ids.update(obj_ids)

        executor_names = set()
        for transform in rules.rule_by_name.keys():
            rule = rules.get_rule(transform)
            executor_names.add(rule.executor )
            assert not rule.is_publish_rule, "Publish rules are not allowed"

        breakpoint()
        # these are the artifacts that we want to add to the conseq file
        starting_artifact_ids = artifact_ids_used_as_inputs.difference(downstream_object_ids)

        # now localize any props that need it in these artifacts
        inputs_to_hardcode = []
        for artifact in j.get_objs_by_ids(starting_artifact_ids):
            tmp_bindings = [("temp", artifact)]
            # localize paths that will be used in scripts
            exec_client.preprocess_xref_inputs(
                j, resolver, tmp_bindings
            )
            # this could be a problem. Is client always going to be a local client? (Is that what we even want?)
            #client = rules.get_client(rule.executor)
            client = exec_client.LocalExecClient({})
            from .exec_client import BoundInput
            inputs, resolver_state = client.preprocess_inputs(
                resolver, [BoundInput("tmp", artifact, None)]
            )

            artifact_dict = dict(inputs["tmp"])
            if artifact_dict.get("type") == "$fileref":
                # skip these because they should be specified on the rule itself
                pass

            if "$manually-added" in artifact_dict:
                del artifact_dict["$manually-added"]

            print("artifact", artifact_dict)
            inputs_to_hardcode.append(artifact_dict)

        output_script = os.path.join(dest_dir, "test.conseq")
        _write_test_script(conseq_file, inputs_to_hardcode, executor_names, output_script)

def _write_test_script(conseq_file, inputs_to_hardcode, executor_names, output_script):
    with open(output_script, "wt") as fd:
        for artifact in inputs_to_hardcode:
            fd.write(f"add-if-missing {json.dumps(artifact, indent=2)}\n\n")

        for executor_name in executor_names:
            if executor_name == "default":
                continue
            fd.write(f"exec-profile {executor_name} {{\n")
            fd.write("  \"type\": \"local\", \"resources\": {\"slots\": \"10\"} }\n\n")
            print(f"Warning: defining an executor profile {executor_name} as local execution")
        fd.write(f"include \"{os.path.relpath(conseq_file, os.path.dirname(output_script))}\"\n")

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

    # print(rules_by_obj_id)

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
                print(
                    indent_str(
                        "Properties shared by all {} rows:".format(len(subset)), indent
                    )
                )
                print(
                    indent_str(
                        tabulate(common_table, common_keys, tablefmt="simple"),
                        indent + 2,
                    )
                )

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
        print(
            indent_str(
                tabulate(variable_table, variable_keys, tablefmt="simple"), indent
            )
        )

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


def forget_cmd(state_dir, rule_name, is_pattern):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))

    if is_pattern:
        pattern = re.compile(rule_name)
        transforms = [
            x.transform for x in j.get_all_executions() if pattern.match(x.transform)
        ]
    else:
        transforms = [rule_name]

    for transform in transforms:
        j.invalidate_rule_execution(transform)


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


def export_cmd(state_dir, depfile, config_file, dest_gs_path, exclude_patterns):
    out = StringIO()

    rules = read_rules(state_dir, depfile, config_file)
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))

    objs = j.find_objs(DEFAULT_SPACE, {})
    vars = rules.vars

    cas_remote = None

    def get_cas_remote():
        nonlocal cas_remote

        if cas_remote is None:
            required = ["S3_STAGING_URL", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
            for name in required:
                if name not in vars:
                    raise Exception(
                        "When pushing to S3, need the following configuration"
                    )

            cas_remote = helper.new_remote(
                vars["S3_STAGING_URL"],
                ".",
                vars["AWS_ACCESS_KEY_ID"],
                vars["AWS_SECRET_ACCESS_KEY"],
            )
        return cas_remote

    def process_value(value):
        if isinstance(value, dict):
            if "$filename" in value:
                url = get_cas_remote().upload_to_cas(value["$filename"])
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
            translated["$manually-added"] = {"$value": "false"}

        return translated

    def reindent(s, ident):
        indent_str = " " * ident
        lines = s.split("\n")

        return "\n".join([lines[0]] + [indent_str + x for x in lines[1:]])

    for obj in objs:
        try:
            props = process_filenames(obj)
        except Exception as e:
            raise Exception(
                "Could not process filenames in artifact: {}".format(repr(obj))
            ) from e
        out.write("add-if-missing {}\n\n".format(reindent(json.dumps(props), 3)))

    def get_key_props(obj):
        props = {}
        for key, value in obj.props.items():
            if isinstance(value, dict) and (
                ("$filename" in value) or ("$file_url" in value) or ("$value" in value)
            ):
                continue
            props[key] = value
        return props

    def value_as_json(value):
        if isinstance(value, tuple):
            return json.dumps([get_key_props(x) for x in value], indent=3)
        else:
            return json.dumps(get_key_props(value), indent=3)

    def skip_remember(name):
        for exclude_pattern in exclude_patterns:
            m = re.match(exclude_pattern, name)
            if m is not None:
                return True
        return False

    executions = j.get_all_executions()
    skipped = 0
    excluded = 0
    for execution in executions:
        if execution.status != "completed":
            skipped += 1
            continue

        if skip_remember(execution.transform):
            excluded += 1
            continue

        out.write('remember-executed transform : "{}"\n'.format(execution.transform))
        for input in execution.inputs:
            out.write(
                '   input "{}" : {}\n'.format(
                    input[0], reindent(value_as_json(input[1]), 3)
                )
            )
        for output in execution.outputs:
            out.write("   output : {}\n".format(reindent(value_as_json(output), 3)))
        out.write("\n")

    log.info(
        "Skipping export of %d executions which did not complete successfully", skipped
    )
    log.info(
        "Skipping export of %d executions which were filtered out via --exclude-remember",
        excluded,
    )
    if dest_gs_path.startswith("s3://") or dest_gs_path.startswith("gs://"):
        log.info("Uploading artifact metadata to %s", dest_gs_path)
        get_cas_remote().upload_str(dest_gs_path, out.getvalue())
    else:
        log.info("Writing artifacts to %s", dest_gs_path)
        with open(dest_gs_path, "wt") as fd:
            fd.write(out.getvalue())


def debugrun(state_dir, depfile, target, override_vars, config_file):
    db_path = os.path.join(state_dir, "db.sqlite3")
    print("opening", db_path)
    j = dep.open_job_db(db_path)

    rules = read_rules(state_dir, depfile, config_file)

    for var, value in override_vars.items():
        rules.set_var(var, value)

    rule = rules.get_rule(target)
    queries, predicates = convert_input_spec_to_queries(
        rules.jinja2_env, rule, rules.vars
    )
    for q in queries:
        t = dep.Template([q], [], rule.name)
        applications = j.query_template(t)
        log.info("{} matches for {}".format(len(applications), q))

    applications = j.query_template(dep.Template(queries, predicates, rule.name))
    log.info("{} matches for entire rule".format(len(applications)))


def gc(state_dir):
    db_path = os.path.join(state_dir, "db.sqlite3")

    if not os.path.exists(state_dir) or not os.path.exists(db_path):
        log.warning(
            "Nothing to do (No such directory: {} or missing db.sqlite3 file)".format(
                state_dir
            )
        )
        return

    j = dep.open_job_db(db_path)

    all_job_dirs = [
        os.path.join(state_dir, fn)
        for fn in os.listdir(state_dir)
        if re.match("r[0-9]+", fn)
    ]
    job_dirs_in_use = set(
        [e.job_dir for e in j.get_all_executions() if e.job_dir is not None]
    )

    # make sure the jobdirs are a subset of all the job dirs we've found
    # print("job in use", list(job_dirs_in_use)[:10])
    # print("all_job_dirs", list(all_job_dirs)[:10])
    assert job_dirs_in_use.issubset(all_job_dirs)

    for job_dir in all_job_dirs:
        if job_dir in job_dirs_in_use:
            continue

        # one more final check because we're about to blow away a directory
        assert job_dir.startswith(state_dir)
        log.warning("Removing unused directory: %s", job_dir)
        shutil.rmtree(job_dir)

    j.gc()


def _rules_to_dot(rules):
    """
    :return: a graphviz graph in dot syntax approximating the execution DAG
    """
    stmts = []
    objs = {}
    rule_nodes = {}

    def add_obj(type):
        if type in objs:
            return objs[type]["id"]
        id = len(objs)
        objs[type] = dict(id=id, type=type)
        return id

    def add_rule(rule_name, filename):
        if rule_name in rule_nodes:
            return rule_nodes[rule_name]["id"]
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
            'r{} [shape=box, style="filled", fillcolor="gray", label="{}\n{}"]'.format(
                node["id"], node["name"], node["filename"]
            )
        )

    for obj in objs.values():
        prop_values = ["type=" + obj["type"]]
        label = "\\n".join(prop_values)
        stmts.append('o{} [label="{}"]'.format(obj["id"], label))

    return "digraph { " + (";\n".join(set(stmts))) + " } "


def alt_dot(state_dir, depfile, config_file):
    rules = read_rules(state_dir, depfile, config_file)
    print(_rules_to_dot(rules))


def superdot(state_dir, depfile, config_file):
    from .scheduler import construct_dataflow, graph_to_dot

    rules = read_rules(state_dir, depfile, config_file)
    g = construct_dataflow(rules)

    with open("dump.dot", "w") as fd:
        fd.write(graph_to_dot(g))
