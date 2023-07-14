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
from conseq.dep import Obj, PUBLIC_SPACE
from conseq.depexec import (
    convert_input_spec_to_queries,
    remove_obj_and_children,
)
from conseq.util import indent_str
import re
from conseq.template import create_jinja2_env
from conseq.config import get_staging_url

log = logging.getLogger(__name__)


def print_rules(state_dir, depfile, config_file, mode, rule_name):
    rules = read_rules(state_dir, depfile, config_file, create_jinja2_env())
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


def localize_if_necessary(resolver, value):
    if isinstance(value, dict):
        assert len(value) == 1
        if "$file_url" in value:
            url = value["$file_url"]
            return resolver.resolve(url), True
        elif "$value" in value:
            return value["$value"], False
        elif "$filename" in value:
            return value["$filename"], False
        else:
            raise Exception(f"unhandled value: {value}")
    else:
        return value, False


def localize_cmd(state_dir, space_, predicates, depfile, config_file):
    rules = read_rules(state_dir, depfile, config_file, create_jinja2_env())

    resolver = xref.Resolver(state_dir, rules.vars)

    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    subset = j.find_objs(PUBLIC_SPACE, dict(predicates))
    for obj in subset:
        for k, v in obj.props.items():
            value, needed_localization = localize_if_necessary(resolver, v)
            if needed_localization:
                log.info("resolved %s to %s", v, value)


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


def stage_cmd(export_file, conseq_file, output_script):
    from conseq import depexec, exec_client
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"Populating temp repo at {tmpdir}")
        # First import the export into a temp database
        db_path = os.path.join(tmpdir, "db.sqlite3")
        j = dep.open_job_db(db_path)

        export_contents = read_rules(
            tmpdir, export_file, config_file=None, jinja2_env=create_jinja2_env()
        )

        # process add-if-missing statements
        depexec.reconcile_db(
            j,
            export_contents.get_rule_specifications(),
            export_contents.objs,
            export_contents.types.values(),
        )

        # handle the remember-executed statements
        with j.transaction():
            for exec_ in export_contents.remember_executed:
                j.remember_executed(exec_)

        # now try to apply the rules in the conseq file provided to find input artifacts

        rules = read_rules(
            tmpdir, conseq_file, config_file=None, jinja2_env=create_jinja2_env()
        )
        # resolver = xref.Resolver(tmpdir, rules.vars)

        # process add-if-missing statements in the rule file
        depexec.reconcile_db(
            j,
            rules.get_rule_specifications(),
            rules.objs,
            rules.types.values(),
            force=False,
            print_missing_objs=False,
        )

        applications = []
        from collections import Counter

        application_count_per_rule = Counter()
        for rule_name in rules.rule_by_name.keys():
            rule = rules.get_rule(rule_name)
            queries, predicates = convert_input_spec_to_queries(
                rules.jinja2_env, rule, rules.vars
            )
            applications_for_rule = j.query_template(
                dep.Template(queries, predicates, rule.name)
            )
            applications.extend(applications_for_rule)
            application_count_per_rule.update({rule_name: len(applications_for_rule)})

        print(f"Found the following executions:")
        for rule_name, count in application_count_per_rule.items():
            print(f"  {rule_name}: {count} applications")

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

        for transform in rules.rule_by_name.keys():
            rule = rules.get_rule(transform)
            if rule.executor not in rules.exec_clients:
                print(
                    f"Warning: {rule.name} uses execution profile {rule.executor} which does not appear in this file. You may need to manually add this."
                )
            assert not rule.is_publish_rule, "Publish rules are not allowed"

        # these are the artifacts that we want to add to the conseq file
        starting_artifact_ids = artifact_ids_used_as_inputs.difference(
            downstream_object_ids
        )

        # now localize any props that need it in these artifacts
        inputs_to_hardcode = []
        from .types import InputsType

        for artifact in j.get_objs_by_ids(starting_artifact_ids):
            # tmp_bindings: InputsType = [("temp", artifact)]
            # localize paths that will be used in scripts
            # exec_client.preprocess_xref_inputs(j, resolver, tmp_bindings)

            # this could be a problem. Is client always going to be a local client? (Is that what we even want?)
            # client = rules.get_client(rule.executor)
            # client = exec_client.LocalExecClient({})
            # from .exec_client import BoundInput

            # inputs, resolver_state = client.preprocess_inputs(
            #     resolver, [BoundInput("tmp", artifact, None)]
            # )

            artifact_dict = dict(artifact.props)
            if artifact_dict.get("type") == "$fileref":
                # skip these because they should be specified on the rule itself
                pass

            if "$manually-added" in artifact_dict:
                del artifact_dict["$manually-added"]

            # print("artifact", artifact_dict)
            inputs_to_hardcode.append(artifact_dict)

        _write_test_script(conseq_file, inputs_to_hardcode, output_script)


def _write_test_script(conseq_file, inputs_to_hardcode, output_script):
    with open(output_script, "wt") as fd:
        for artifact in inputs_to_hardcode:
            fd.write(f"add-if-missing {json.dumps(artifact, indent=2)}\n\n")

        fd.write(
            f'include "{os.path.relpath(conseq_file, os.path.dirname(output_script))}"\n'
        )


def downstream_cmd(state_dir, _space, predicates):

    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))

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

    subset = j.find_objs(PUBLIC_SPACE, dict(predicates))
    for o in subset:
        print(f"artifact {o} has the following downstream:")
        downstreams = j.find_all_reachable_downstream_objs([o.id])
        for downstream in downstreams:
            rules = rules_by_obj_id[downstream.id]
            downstream_id = downstream.id
            print(f"  {downstream_id}: rules {rules}")
        print("")
    # subset is list of key -> value pairs


def ls_cmd(state_dir, _space, predicates, groupby, columns):
    from tabulate import tabulate
    from conseq import depquery

    cache_db = xref.open_cache_db(state_dir)

    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    subset = j.find_objs(PUBLIC_SPACE, dict(predicates))
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


def rm_cmd(state_dir, dry_run, _space, query):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))

    root_objs = j.find_objs(PUBLIC_SPACE, query)
    root_obj_ids = [o.id for o in root_objs]

    remove_obj_and_children(j, root_obj_ids, dry_run)


def list_cmd(state_dir):
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    j.dump()


def export_cmd(state_dir, depfile, config_file, dest_gs_path, exclude_patterns):
    out = StringIO()

    rules = read_rules(state_dir, depfile, config_file, create_jinja2_env())
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))

    objs = j.find_objs(PUBLIC_SPACE, {})
    vars = rules.vars

    cas_remote = None

    def get_cas_remote():
        nonlocal cas_remote

        if cas_remote is None:
            if "S3_STAGING_URL" not in vars and "STAGING_URL" not in vars:
                raise Exception(
                    "When pushing to cloud, need the following configuration STAGING_URL"
                )

            cas_remote = helper.new_remote(get_staging_url(vars), ".")
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


from typing import Optional


def _application_to_dict(resolver, bindings):
    result = {}

    def _obj_to_dict(obj):
        result = {}
        for name, value in obj.props.items():
            result[name], _ = localize_if_necessary(resolver, value)
        return result

    for name, objs in bindings:
        if isinstance(objs, Obj):
            result[name] = _obj_to_dict(objs)
        else:
            result[name] = [_obj_to_dict(obj) for obj in objs]

    return result


def debugrun(
    state_dir,
    depfile,
    target,
    override_vars,
    config_file: Optional[str],
    save_inputs_filename: Optional[str],
):
    db_path = os.path.join(state_dir, "db.sqlite3")
    print("opening", db_path)
    j = dep.open_job_db(db_path)

    rules = read_rules(state_dir, depfile, config_file, create_jinja2_env())

    resolver = xref.Resolver(state_dir, rules.vars)

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

    if save_inputs_filename:
        index = 0
        for space, bindings, rule_name in applications:
            index += 1
            assert space == PUBLIC_SPACE  # space doesn't actually get used anymore
            inputs = _application_to_dict(resolver, bindings)
            if len(applications) == 1:
                output_filename = save_inputs_filename
            else:
                output_filename = f"{save_inputs_filename}.{index}"
            log.info(f"Writing inputs for {rule_name} to {output_filename}")
            with open(output_filename, "wt") as fd:
                fd.write(json.dumps(inputs, indent=2))


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
