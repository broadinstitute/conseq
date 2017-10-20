from conseq import dep
from conseq import depexec
from boto.s3.connection import S3Connection
from boto.s3.key import Key
import re
import json
import os
import datetime
import collections

def rewrite_file_refs(obj, stage_dir, url_prefix):
    # returns new_props, filenames (pairs of local -> remote)

    def rewrite_filename(fn):
        prefix = fn[:len(stage_dir)+1]
        assert prefix == stage_dir+"/"
        suffix = fn[len(stage_dir)+1:]
        return url_prefix+"/"+suffix

    props = obj.props
    new_props = {}
    translations = []
    for k, v in props.items():
        if isinstance(v, dict) and "$filename" in v:
            filename = v["$filename"]
            new_url = rewrite_filename(filename)
            translations.append( (filename, new_url) )
            new_props[k] = {"$file_url": new_url}
        else:
            new_props[k] = v

    return (new_props, translations)

def split_url(s):
    m = re.match("s3://([^/]+)/(.*)", s)
    if m == None:
        raise Exception("Could not parse s3 url: {}".format(s))
    return m.groups()

def upload_single_file(bucket, path, filename):
    k = Key(bucket)
    k.key = path
    k.set_contents_from_filename(filename)

def drop_prefix(x, prefix):
    assert x[:len(prefix)] == prefix
    return x[len(prefix):]

def upload_files(bucket, path_pairs):
    for filename, new_url in path_pairs:
        print("Uploading {} -> {}".format(filename, new_url))

        bucket_name, path = split_url(new_url)
        assert bucket_name == bucket.name
        if os.path.isdir(filename):
            for root, directories, filenames in os.walk(filename):
                for _filename in filenames:
                    src_filename = os.path.join(root,_filename)
                    dest_path = path+drop_prefix(src_filename, filename)
                    print("Uploading subfile {} -> {}".format(src_filename, dest_path))
                    upload_single_file(bucket, dest_path, src_filename)
        else:
            upload_single_file(bucket, path, filename)

def export_artifacts(state_dir, url, config_file):
    config = depexec.load_config(config_file)
    j = dep.open_state_dir(state_dir)

    # I wonder if a repo will every get large enough that we won't want to do this in memory.  My guess is, no.
    objs = j.find_objs(dep.DEFAULT_SPACE, dict())
    new_objs = []
    all_translations = []
    for o in objs:
        new_props, translations = rewrite_file_refs(o, state_dir, url)
        all_translations.extend(translations)
        new_objs.append(new_props)

    artifacts = json.dumps(new_objs)

    c = S3Connection(config["AWS_ACCESS_KEY_ID"], config["AWS_SECRET_ACCESS_KEY"])
    bucket_name, path = split_url(url)
    bucket = c.get_bucket(bucket_name)
    upload_files(bucket, all_translations)

    k = Key(bucket)
    k.key = path+"/artifacts.json"
    k.set_contents_from_string(artifacts)

def import_artifacts(state_dir, url, config_file):
    config = depexec.load_config(config_file)

    if not os.path.exists(state_dir):
        os.makedirs(state_dir)
    j = dep.open_state_dir(state_dir)

    c = S3Connection(config["AWS_ACCESS_KEY_ID"], config["AWS_SECRET_ACCESS_KEY"])
    bucket_name, path = split_url(url)
    bucket = c.get_bucket(bucket_name)

    k = Key(bucket)
    k.key = path+"/artifacts.json"
    artifacts = json.loads(k.get_contents_as_string().decode("utf-8"))

    timestamp = datetime.datetime.now().isoformat()
    for artifact in artifacts:
        j.add_obj(dep.DEFAULT_SPACE, timestamp, artifact)

def rule_execution_as_json(rule_execution, execution_result):
    def obj_key_props(obj):
        obj_json = {}

        for prop, value in obj.props.items():
            # drop any non-key props
            if not isinstance(value, dict):
                obj_json[prop] = value
        return obj_json

    def obj_or_list_key_props(objs):
        if isinstance(objs, tuple):
            return tuple([obj_key_props(x) for x in objs])
        else:
            return obj_key_props(objs)

    inputs_json = []
    for name, value in rule_execution.inputs:
        input_json = {"name": name, "value": obj_or_list_key_props(value)}
        inputs_json.append(input_json)

    outputs_json = []
    for output in execution_result.outputs:
        outputs_json.append(obj_key_props(output))

    return rule_execution.transform, inputs_json, outputs_json


from conseq import helper

import logging
log = logging.getLogger(__name__)

def upload_and_rewrite(remote, objs):
    # collect all of the filenames needing to be pushed
    filenames = set()
    filenames_to_skip = set()

    for props in objs:
        for k, v in props.items():
            if isinstance(v, dict) and "$filename" in v:
                filename = os.path.abspath(v["$filename"])
                assert not os.path.isdir(filename), "Cannot export artifacts which reference a directory: {}".format(filename)
                filenames.add(filename)

    # now push them all
    name_mapping = helper.push_to_cas(remote, filenames, return_full_url=True)

    rewritten_objs = []
    for props in objs:
        rewritten_props = {}
        for k, v in props.items():
            if isinstance(v, dict) and "$filename" in v:
                filename = os.path.abspath(v["$filename"])
                if filename in filenames_to_skip:
                    rewritten_props[k] = {"$file_url": "invalid-due-cannot-upload-dir"}
                else:
                    new_url = name_mapping[filename]
                    rewritten_props[k] = {"$file_url": new_url}
            else:
                rewritten_props[k] = v
        rewritten_objs.append(rewritten_props)

    return rewritten_objs

def export_conseq(state_dir, output_file, cas_remote_url):
    by_group = collections.defaultdict(lambda: [])
    j = dep.open_state_dir(state_dir)

    objs = j.find_objs(dep.DEFAULT_SPACE, dict())
    objs = [o.props for o in objs]

    if cas_remote_url:
        cas_remote = helper.Remote(cas_remote_url, ".")
        objs = upload_and_rewrite(cas_remote, objs)

    if output_file is None:
        import sys
        fd = sys.stdout
    else:
        fd = open(output_file, "wt")

    for obj in objs:
        by_group[obj.get("type", "")].append(obj)

    for group, objs in by_group.items():
        fd.write("# Objects with type \"{}\"\n".format(group))
        for obj in objs:
            fd.write("add-if-missing ")
            json.dump(obj, fd, indent=2)
            fd.write("\n")
        fd.write("\n")

    fd.write("# Rule executions\n")
    with j.transaction():
        for rule_execution in j.rule_set:
            if rule_execution.execution_id is None:
                print("Skipping ", rule_execution)
                continue

            execution_result = j.log.get( rule_execution.execution_id )
            if execution_result is None:
                print("Skipping {} because while we had an execution id {} but appeared to be missing from the db".format(rule_execution, rule_execution.execution_id))
                continue

            transform, inputs, outputs = rule_execution_as_json(rule_execution, execution_result)
            fd.write("remember-executed\n")
            fd.write("  transform: {}\n".format(json.dumps(transform)))
            for input in inputs:
                fd.write("  input "+json.dumps(input["name"])+": "+json.dumps(input["value"])+"\n")
            for output in outputs:
                fd.write("  output: "+json.dumps(output)+"\n")
            fd.write("\n\n")

    if output_file is not None:
        fd.close()

def publish_artifacts(state_dir, cas_remote_url, queries, dest_url, config_file):
    config = depexec.load_config(config_file)
    accesskey = config['AWS_ACCESS_KEY_ID']
    secretaccesskey = config['AWS_SECRET_ACCESS_KEY']

    by_group = collections.defaultdict(lambda: [])
    j = dep.open_state_dir(state_dir)

    objs = set()
    for query in queries:
        objs.update(j.find_objs(dep.DEFAULT_SPACE, query))
    objs = list(objs)
    obj_props = [o.props for o in objs]

    if cas_remote_url:
        cas_remote = helper.Remote(cas_remote_url, ".", accesskey=accesskey, secretaccesskey=secretaccesskey)
        obj_props = upload_and_rewrite(cas_remote, obj_props)

    for i, props in enumerate(obj_props):
        by_group[props.get("type", "")].append( (objs[i], obj_props) )

    # order by type to make things easier to read through by eye
    artifacts = []
    for group, obj_tuples in by_group.items():
        for obj, obj_props in obj_tuples:
            # extend by adding provenance?
            artifacts.append(dict(properties=obj_props))

    remote = helper.Remote(os.path.dirname(dest_url), ".", accesskey=accesskey, secretaccesskey=secretaccesskey)
    remote.upload_str(os.path.basename(dest_url), json.dumps(dict(artifacts=artifacts), indent=2))
