from conseq import dep
from conseq import depexec
from boto.s3.connection import S3Connection
from boto.s3.key import Key
import re
import json
import os
import datetime

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
