import re
import logging
import os
import hashlib
import argparse
import json

from boto.s3.connection import S3Connection
from boto.s3.key import Key

log = logging.getLogger(__name__)

def parse_remote(path, accesskey=None, secretaccesskey=None):
    m = re.match("^s3://([^/]+)/(.*)$", path)
    assert m != None, "invalid remote path: {}".format(path)
    bucket_name = m.group(1)
    path = m.group(2)

    c = S3Connection(accesskey, secretaccesskey)
    bucket = c.get_bucket(bucket_name)

    return bucket, path

class Remote:
    def __init__(self, remote_url, local_dir, accesskey=None, secretaccesskey=None):
        self.remote_url = remote_url
        self.local_dir = local_dir
        self.bucket, self.remote_path = parse_remote(remote_url, accesskey, secretaccesskey)

    def exists(self, remote):
        remote_path = self.remote_path + "/" + remote
        key = self.bucket.get_key(remote_path)
        return key != None

    # TODO: make download atomic by dl and rename (assuming get_contents_to_filename doesn't already)
    def download(self, remote, local, ignoreMissing=False):
        # maybe upload and download should use trailing slash to indicate directory should be uploaded instead of just a file
        remote_path = self.remote_path + "/" + remote
        local = self.local_dir + "/" + local
        key = self.bucket.get_key(remote_path)
        if key != None:
            # if it's a file, download it
            log.info("Downloading file %s to %s", remote_path, local)
            key.get_contents_to_filename(local)
        else:
            # download everything with the prefix
            transferred = 0
            for key in self.bucket.list(prefix=remote_path):
                rest = drop_prefix(remote_path+"/", key.key)
                if not os.path.exists(local):
                    os.makedirs(local)
                local_path = os.path.join(local, rest)
                log.info("Downloading dir %s (%s to %s)", remote, key.name, local_path)
                key.get_contents_to_filename(local_path)
                transferred += 1

            if transferred == 0 and not ignoreMissing:
                raise Exception("Could not find {}".format(local))

    def upload(self, local, remote, ignoreMissing=False):
        # maybe upload and download should use trailing slash to indicate directory should be uploaded instead of just a file
        remote_path = self.remote_path + "/" + remote
        #local_path = os.path.join(local, remote)
        local_path = local

        if os.path.exists(local_path):
            if os.path.isfile(local_path):
                # if it's a file, upload it
                key = Key(self.bucket)
                key.name = remote_path
                log.info("Uploading file %s to %s", local, remote)
                key.set_contents_from_filename(local_path)
            else:
                # upload everything in the dir
                for fn in os.listdir(local):
                    full_fn = os.path.join(local, fn)
                    if os.path.isfile(full_fn):
                        k = Key(self.bucket)
                        k.key = os.path.join(remote_path, fn)
                        log.info("Uploading dir %s (%s to %s)", local, fn, fn)
                        k.set_contents_from_filename(full_fn)
        elif not ignoreMissing:
            raise Exception("Could not find {}".format(local))

    def download_as_str(self, remote):
        remote_path = self.remote_path+"/"+remote
        key = self.bucket.get_key(remote_path)
        if key == None:
            return None
        return key.get_contents_as_string()

    def upload_str(self, remote, text):
        remote_path = self.remote_path+"/"+remote
        k = Key(self.bucket)
        k.key = remote_path
        k.set_contents_from_string(text)

def drop_prefix(prefix, value):
    assert value[:len(prefix)] == prefix, "Expected {} to be prefixed with {}".format(repr(value), repr(prefix))
    return value[len(prefix):]


def calc_hash(filename):
    h = hashlib.sha256()
    with open(filename, "rb") as fd:
        for chunk in iter(lambda: fd.read(10000), b''):
            h.update(chunk)
    return h.hexdigest()

def push_to_cas(remote, filenames):
    name_mapping = {}

    for filename in filenames:
        hash = calc_hash(filename)
        remote_name = "CAS/{}".format(hash)
        if remote.exists(remote_name):
            log.info("Skipping upload of %s because %s already exists", filename, remote_name)
        else:
            remote.upload(filename, remote_name)
        name_mapping[filename] = remote_name

    return name_mapping

def pull(remote, filename_mapping):
    for local_path, remote_path in filename_mapping.items():
        remote.download(remote_path, local_path)


def push_cmd(args, config):
    remote = Remote(args.remote_url, args.local_dir, config["AWS_ACCESS_KEY_ID"], config["AWS_SECRET_ACCESS_KEY"])
    if args.cas:
        push_to_cas(remote, args.filenames)
    else:
        for filename in args.filenames:
            remote.upload(filename, filename)

def pull_cmd(args, config):
    remote = Remote(args.remote_url, args.local_dir, config["AWS_ACCESS_KEY_ID"], config["AWS_SECRET_ACCESS_KEY"])
    for file_mapping in args.file_mappings:
        if ":" in file_mapping:
            remote_path, local_path = file_mapping.split(":")
        else:
            remote_path = local_path = file_mapping
        remote.download(remote_path, local_path)

def read_config(filename):
    config = {}
    with open(filename, "rt") as fd:
        for line in fd.readlines():
            m = re.match("\\s*(\\S+)\\s*=\\s*\"([^\"]+)\"", line)
            assert m != None
            config[m.group(1)] = m.group(2)
    return config

def publish_cmd(args, config):
    remote = Remote(args.remote_url, args.local_dir, config["AWS_ACCESS_KEY_ID"], config["AWS_SECRET_ACCESS_KEY"])
    published_files_root = drop_prefix(args.local_dir, os.path.abspath(os.path.dirname(args.results_json)))

    with open(args.results_json) as fd:
        results = json.load(fd)

    t_published = {}
    for k, v in results['outputs'].items():
        if isinstance(v, dict) and "$filename" in v:
            filename = os.path.join(published_files_root, v["$filename"])
            file_url = remote.upload(filename, filename)
            assert file_url is not None
            t_published[k] = {"$file_url": file_url}
        else:
            t_published[k] = v

    results["outputs"] = t_published
    new_results_json = json.dumps({"outputs": t_published}, fd)
    remote.upload_str(os.path.join(published_files_root, "results.json"), new_results_json)

def main():
    parser = argparse.ArgumentParser("push or pull files from cloud storage")
    parser.set_defaults(func=None)
    parser.add_argument("--config", "-c", help="path to config file")

    subparsers = parser.add_subparsers()

    push_parser = subparsers.add_parser("push")
    push_parser.add_argument("--cas", help="Use content addressable storage", action='store_true')
    push_parser.add_argument("remote_url", help="base remote url to use")
    push_parser.add_argument("local_dir")
    push_parser.add_argument("filenames", nargs="+")
    push_parser.set_defaults(func=push_cmd)

    publish_parser = subparsers.add_parser("publish")
    publish_parser.add_argument("remote_url")
    publish_parser.add_argument("local_dir")
    publish_parser.add_argument("publish_json")
    publish_parser.set_defaults(func=publish_cmd)

    pull_parser = subparsers.add_parser("pull")
    pull_parser.add_argument("remote_url", help="base remote url to pull from")
    pull_parser.add_argument("local_dir")
    pull_parser.add_argument("file_mappings", help="mappings of remote paths to local paths of the form 'remote:local'", nargs="+")
    pull_parser.set_defaults(func=pull_cmd)

    args = parser.parse_args()
    config = {}
    if args.config is not None:
        config = read_config(args.config)

    logging.basicConfig(level=logging.INFO)

    if args.func is None:
        parser.print_help()
    else:
        args.func(args, config)

if __name__ == "__main__":
    main()
