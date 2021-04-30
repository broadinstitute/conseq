import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
from typing import Dict, List, Optional, Tuple

from boto.s3.bucket import Bucket
from boto.s3.connection import S3Connection
from boto.s3.key import Key
import traceback

log = logging.getLogger(__name__)

def _parse_remote(path: str) -> Tuple[
    str, str]:
    m = re.match("^s3://([^/]+)/(.*)$", path)
    assert m != None, "invalid remote path: {}".format(path)
    bucket_name = m.group(1)
    path = m.group(2)
    return bucket_name, path


def download_s3_as_string(remote):
    assert remote.startswith("s3:")
    bucket, remote_path = _parse_remote(remote)

    key = bucket.get_key(remote_path)
    if key == None:
        return None

    value = key.get_contents_as_string()
    return value.decode("utf-8")


class StorageConnection:
    def get_bucket(self, bucket_name):
        raise NotImplemented()

class S3StorageConnection(StorageConnection):
    def __init__(self, accesskey, secretaccesskey):
        self.c = S3Connection(accesskey, secretaccesskey)
    def get_bucket(self, bucket_name):
        return self.c.get_bucket(bucket_name, validate=False)
    def get_generation_id(self, key_obj):
        raise NotImplemented

def new_remote(remote_url, local_dir, accesskey, secretaccesskey):
    sc = S3StorageConnection(accesskey, secretaccesskey)
    return Remote(remote_url, local_dir, sc)

class Remote:
    def __init__(self, remote_url: str, local_dir: str, sc : StorageConnection):
        self.connection = sc
        self.remote_url = remote_url
        self.local_dir = local_dir
        self.bucket_name, self.remote_path = _parse_remote(remote_url)
        self.bucket = self.get_bucket(self.bucket_name)

    def get_bucket(self, bucket_name : str):
        return self.connection.get_bucket(bucket_name)

    def exists(self, remote: str) -> bool:
        if remote.startswith("s3:"):
            bucket_name, remote_path = _parse_remote(remote)
            bucket = self.get_bucket(bucket_name)
        else:
            bucket = self.bucket
            remote_path = os.path.normpath(self.remote_path + "/" + remote)

        key = bucket.get_key(remote_path)
        return key != None

    def _download_object(self, source_bucket, source_key, dest_path, stage_dir, skipExisting):
        if os.path.exists(dest_path) and skipExisting:
            log.info("Already s3://%s/%s downloaded as %s", source_bucket, source_key, dest_path)
            return

        bucket = self.get_bucket(source_bucket)
        key = bucket.get_key(source_key)
        assert key

        def download_to(dest):
            if not os.path.exists(os.path.dirname(dest)):
                os.makedirs(os.path.dirname(dest))
            for i in range(100):
                temp_name = dest + ".in.progress." + str(i)
                if not os.path.exists(temp_name):
                    break

            key.get_contents_to_filename(temp_name)
            os.rename(temp_name, dest)

        if stage_dir is not None:
            # if hash is defined for this object, use this for caching
            hash = key.get_metadata("sha256")
            if hash is not None:
                stage_path = os.path.join(stage_dir, "CAS", hash)
            else:
                # otherwise, fall back to using path and generation ID/etag
                etag = key.get_etag()
                stage_path = os.path.join(stage_dir, "gcs", source_bucket, source_key, etag)

            download_to(stage_path)

            if not os.path.exists(os.path.dirname(dest_path)):
                os.makedirs(os.path.dirname(dest_path))
            os.link(stage_path, dest_path)
        else:
            download_to(dest_path)

    def download(self, remote: str, local : str, ignoreMissing=False, skipExisting=True, stage_dir=None):
        # maybe upload and download should use trailing slash to indicate directory should be uploaded instead of just a file
        if not local.startswith("/"):
            local = os.path.normpath(self.local_dir + "/" + local)

        if remote.startswith("s3:"):
            bucket_name, remote_path = _parse_remote(remote)
            bucket = self.get_bucket(bucket_name)
        else:
            bucket = self.bucket
            bucket_name = self.bucket_name
            remote_path = os.path.normpath(self.remote_path + "/" + remote)

        key = bucket.get_key(remote_path)
        if key != None:
            # if it's a file, download it
            abs_local = os.path.abspath(local)
            log.info("Downloading file %s to %s", remote_path, abs_local)

            self._download_object(bucket_name, remote_path, abs_local, stage_dir,skipExisting)
        else:
            # download everything with the prefix
            transferred = 0
            for key in bucket.list(prefix=remote_path):
                rest = drop_prefix(remote_path + "/", key.key)
                if not os.path.exists(local):
                    os.makedirs(local)
                local_path = os.path.join(local, rest)
                log.info("Downloading dir %s (%s to %s)", remote, key.name, local_path)
                self._download(bucket_name, key.name, local_path, stage_dir=stage_dir)
                transferred += 1

            if transferred == 0 and not ignoreMissing:
                raise Exception("Could not find {}".format(local))

    def upload_to_cas(self, filename):
        "upload a single file to CAS"
        mapping = push_to_cas(self, [filename], return_full_url=True)
        paths = list(mapping.values())
        assert len(paths) == 1
        return paths[0]

    def upload(self, local, remote, ignoreMissing=False, force=False, hash=None):
        # maybe upload and download should use trailing slash to indicate directory should be uploaded instead of just a file
        assert not remote.startswith("/")
        # assert not local.startswith("/")
        remote_path = os.path.normpath(self.remote_path + "/" + remote)
        local_path = os.path.normpath(os.path.join(self.local_dir, local))
        # cope when case where local was passed as an abs path
        # local = os.path.relpath(local, self.local_dir)
        # assert not local.startswith("."), "local={}, local_dir={}".format(local, self.local_dir)
        # local_path = local
        uploaded_url = None

        if os.path.exists(local_path):
            if os.path.isfile(local_path):
                # if it's a file, upload it
                uploaded_url = "s3://" + self.bucket.name + "/" + remote_path
                if self.bucket.get_key(remote_path) is None or force:
                    key = Key(self.bucket)
                    key.name = remote_path
                    log.info("Uploading file %s to %s", local, uploaded_url)
                    key.set_contents_from_filename(local_path)
                    if hash is None:
                        hash = calc_hash(local_path)
                    key.set_metadata("sha256", hash)
            else:
                # upload everything in the dir
                assert hash is None
                for fn in os.listdir(local_path):
                    full_fn = os.path.join(local_path, fn)
                    if os.path.isfile(full_fn):
                        r = os.path.join(remote_path, fn)
                        if self.bucket.get_key(r) is None or force:
                            k = Key(self.bucket)
                            k.key = r
                            log.info("Uploading dir %s (%s to %s)", local_path, fn, fn)
                            k.set_contents_from_filename(full_fn)
                            hash = calc_hash(local_path)
                            k.set_metadata("sha256", hash)
                        else:
                            log.info("Uploading dir %s (%s to %s), skiping existing file", local_path, fn, fn)
        elif not ignoreMissing:
            raise Exception("Could not find {}".format(local))

        return uploaded_url

    def download_as_str(self, remote: str, timeout: int = 5) -> str:
        if remote.startswith("s3:"):
            bucket_name, remote_path = _parse_remote(remote)
            bucket = self.get_bucket(bucket_name)
        else:
            bucket = self.bucket
            remote_path = os.path.normpath(self.remote_path + "/" + remote)

        log.debug("downloading as string: %s", remote_path)
        key = bucket.get_key(remote_path)
        if key == None:
            return None

        value = key.get_contents_as_string()
        return value.decode("utf-8")

    def upload_str(self, remote, text):
        if remote.startswith("s3:"):
            bucket_name, remote_path = _parse_remote(remote)
            bucket = self.get_bucket(bucket_name)
        else:
            bucket = self.bucket
            remote_path = os.path.normpath(self.remote_path + "/" + remote)

        k = Key(bucket)
        k.key = remote_path
        log.info("Uploading s3://%s/%s from memory", self.bucket.name, remote_path)
        k.set_contents_from_string(text)


def drop_prefix(prefix, value):
    assert value[:len(prefix)] == prefix, "Expected {} to be prefixed with {}".format(repr(value), repr(prefix))
    return value[len(prefix):]


def calc_hash(filename: str) -> str:
    h = hashlib.sha256()
    with open(filename, "rb") as fd:
        for chunk in iter(lambda: fd.read(10000), b''):
            h.update(chunk)
    return h.hexdigest()


def push_str_to_cas(remote, content, filename="<unknown>"):
    h = hashlib.sha256(content.encode("utf-8"))
    hash = h.hexdigest()

    remote_name = "CAS/{}".format(hash)
    if remote.exists(remote_name):
        log.info("Skipping upload of %s because %s already exists", filename, remote_name)
    else:
        remote.upload_str(remote_name, content)
    return remote_name


def push_to_cas(remote: Remote, filenames: List[str], return_full_url: bool = False) -> Dict[str, str]:
    "upload multiple files to CAS and return mapping of filename to url"
    name_mapping = {}

    for filename in filenames:
        local_filename = os.path.normpath(os.path.join(remote.local_dir, filename))
        hash = calc_hash(local_filename)
        remote_name = "CAS/{}".format(hash)
        if remote.exists(remote_name):
            log.info("Skipping upload of %s because %s already exists", filename, remote_name)
        else:
            remote.upload(filename, remote_name, hash=hash)
        if return_full_url:
            remote_name = remote.remote_url + "/" + remote_name
        name_mapping[filename] = remote_name

    return name_mapping


def _get_files_from_dir(dirname):
    files = []
    for fn in os.listdir(dirname):
        full = os.path.join(dirname, fn)
        if not os.path.isdir(full):
            files.append(full)
    return files


def push(remote, filenames):
    for filename in filenames:
        filename = os.path.join(remote.local_dir, filename)
        if os.path.isdir(filename):
            for fn in _get_files_from_dir(filename):
                remote.upload(fn, fn)
        else:
            remote.upload(filename, filename)


def push_cmd(args, config):
    remote = Remote(args.remote_url, args.local_dir, config["AWS_ACCESS_KEY_ID"], config["AWS_SECRET_ACCESS_KEY"])
    if args.cas:
        push_to_cas(remote, args.filenames)
    else:
        push(remote, args.filenames)


def pull(remote, file_mappings, ignoreMissing=False, skipExisting=True, stage_dir=None):
    for remote_path, local_path in file_mappings:
        log.debug("pull remote_path=%s local_path=%s", remote_path, local_path)
        remote.download(remote_path, local_path, ignoreMissing=ignoreMissing, skipExisting=skipExisting,
                        stage_dir=stage_dir)


def pull_cmd(args, config):
    remote = Remote(args.remote_url, args.local_dir, config["AWS_ACCESS_KEY_ID"], config["AWS_SECRET_ACCESS_KEY"])
    pull(remote, args.file_mappings)


def read_config(filename):
    config = {}
    with open(filename, "rt") as fd:
        for line in fd.readlines():
            m = re.match("\\s*(\\S+)\\s*=\\s*\"([^\"]+)\"", line)
            assert m != None
            config[m.group(1)] = m.group(2)
    return config


def publish_results(results_json_file, remote, published_files_root, results_json_dest):
    if not os.path.exists(results_json_file):
        log.info("Skipping publishing results back. %s does not exist", results_json_file)
        return
    with open(results_json_file) as fd:
        results = json.load(fd)

    outputs_to_publish = []
    for output in results['outputs']:
        rewritten_output = {}
        for k, v in output.items():
            if isinstance(v, dict) and "$filename" in v:
                filename = os.path.join(published_files_root, v["$filename"])
                log.info("Uploading artifact from %s to %s", filename, filename)
                file_url = remote.upload_to_cas(filename)
                assert file_url is not None
                rewritten_output[k] = {"$file_url": file_url}
            else:
                rewritten_output[k] = v
        outputs_to_publish.append(rewritten_output)

    results["outputs"] = outputs_to_publish
    new_results_json = json.dumps(results, sort_keys=True)
    remote.upload_str(results_json_dest, new_results_json)


def convert_json_mapping(d):
    result = []
    for rec in d['mapping']:
        remote = rec['remote']
        local = rec['local']
        assert not local.startswith("/")
        result.append((remote, local))
    return result


def parse_mapping_str(file_mapping):
    assert isinstance(file_mapping, str)
    if ":" in file_mapping:
        remote_path, local_path = file_mapping.split(":")
    else:
        remote_path = local_path = file_mapping
    return (remote_path, local_path)


def exec_config(args, config):
    config_content = download_s3_as_string(args.url)
    if config_content is None:
        raise Exception("Could not open {}".format(args.url))
    config = json.loads(config_content)

    remote = Remote(config['remote_url'], args.local_dir)
    for r in config['pull']:
        remote.download(r['src'], r['dest'])

    for dirname in config['mkdir']:
        if not os.path.exists(dirname):
            os.makedirs(dirname)

    # execute command
    command = config['command']
    stdout_path = config['stdout']
    stderr_path = config['stderr']
    exec_summary_path = config['exec_summary']
    try:
        exec_command_with_capture(command, stderr_path, stdout_path, exec_summary_path, args.local_dir)
    except Exception:
        tb = traceback.format_exc()
        message = "Got exception in exec_command_with_capture():\n"+tb
        print("Got an exception and now desperately attempting to gracefully to communicate it back by writing it to the stderr log")
        print(message)
        with open(stderr_path, "at") as fd:
            fd.write(message)

    # push results
    for r in config['push']:
        remote.upload(r['src'], r['dest'], force=True)


def exec_cmd(args, config):
    remote = Remote(args.remote_url, args.local_dir, config["AWS_ACCESS_KEY_ID"], config["AWS_SECRET_ACCESS_KEY"])
    cas_remote = Remote(args.cas_remote_url, args.local_dir, config["AWS_ACCESS_KEY_ID"],
                        config["AWS_SECRET_ACCESS_KEY"])

    pull_map = []
    if args.download_pull_map is not None:
        dl_pull_map_str = remote.download_as_str(args.download_pull_map)
        pull_map_dict = json.loads(dl_pull_map_str)
        pull_map.extend(convert_json_mapping(pull_map_dict))

    if args.download is not None:
        for mapping_str in args.download:
            pull_map.append(parse_mapping_str(mapping_str))

    pull(remote, pull_map, ignoreMissing=True, skipExisting=not args.forcedl, stage_dir=args.stage_dir)

    exec_command_with_capture(args.command, args.stderr, args.stdout, args.retcode, args.local_dir)

    if args.upload is not None:
        push(remote, args.upload)

    if args.uploadresults is not None:
        results_json_file = "./results.json"
        published_files_root = args.local_dir
        publish_results(results_json_file, cas_remote, published_files_root, args.uploadresults)


def exec_command_with_capture(command, stderr_path, stdout_path, retcode_path, local_dir):
    stderr_fd = None
    if stderr_path is not None:
        stderr_fd = os.open(os.path.join(local_dir, stderr_path), os.O_WRONLY | os.O_APPEND | os.O_CREAT)

    stdout_fd = None
    if stdout_path is not None:
        stdout_fd = os.open(os.path.join(local_dir, stdout_path), os.O_WRONLY | os.O_APPEND | os.O_CREAT)

    log.info("executing {}".format(command))
    try:
        retcode = subprocess.call(command, stdout=stdout_fd, stderr=stderr_fd, cwd=local_dir)
    finally:
        os.close(stdout_fd)
        os.close(stderr_fd)
    log.info("Command returned {}".format(retcode))

    if retcode_path is not None:
        fd = open(os.path.join(local_dir, retcode_path), "wt")
        state = "success" if retcode == 0 else "failed"
        fd.write(json.dumps({"retcode": retcode, "state": state}))
        fd.close()


def main(varg=None):
    parser = argparse.ArgumentParser("push or pull files from cloud storage")
    parser.add_argument("--config", "-c", help="path to config file")

    subparsers = parser.add_subparsers()

    push_parser = subparsers.add_parser("push")
    push_parser.add_argument("--cas", help="Use content addressable storage", action='store_true')
    push_parser.add_argument("remote_url", help="base remote url to use")
    push_parser.add_argument("local_dir")
    push_parser.add_argument("filenames", nargs="+")
    push_parser.set_defaults(func=push_cmd)

    exec_parser = subparsers.add_parser("exec")
    exec_parser.add_argument("remote_url")
    exec_parser.add_argument("cas_remote_url")
    exec_parser.add_argument("local_dir")
    exec_parser.add_argument("--download_pull_map", "-f")
    exec_parser.add_argument("--download", "-d", default=[], action="append")
    exec_parser.add_argument("--upload", "-u", default=[], action="append")
    exec_parser.add_argument("--stdout", "-o")
    exec_parser.add_argument("--stderr", "-e")
    exec_parser.add_argument("--retcode", "-r")
    exec_parser.add_argument("--forcedl", help="Force download of files even if the destination already exists")
    exec_parser.add_argument("--stage", help="directory to use for staging in local CAS", dest="stage_dir")
    exec_parser.add_argument("--uploadresults",
                             help="If set, upload results.json to this location and all other associated files to CAS")
    exec_parser.add_argument("command", nargs=argparse.REMAINDER)
    exec_parser.set_defaults(func=exec_cmd)

    exec_config_parser = subparsers.add_parser("exec-config")
    exec_config_parser.add_argument("url")
    exec_config_parser.add_argument("--local_dir", default=".")
    exec_config_parser.set_defaults(func=exec_config)

    pull_parser = subparsers.add_parser("pull")
    pull_parser.add_argument("remote_url", help="base remote url to pull from")
    pull_parser.add_argument("local_dir")
    pull_parser.add_argument("file_mappings", help="mappings of remote paths to local paths of the form 'remote:local'",
                             nargs="+")
    pull_parser.set_defaults(func=pull_cmd)

    log.info("helper.main parameters: %s", varg)

    args = parser.parse_args(varg)
    config = {}
    if args.config is not None:
        config = read_config(args.config)
    else:
        config["AWS_ACCESS_KEY_ID"] = os.getenv("AWS_ACCESS_KEY_ID")
        config["AWS_SECRET_ACCESS_KEY"] = os.getenv("AWS_SECRET_ACCESS_KEY")

    logging.basicConfig(level=logging.INFO)

    print(args)

    if args.func is None:
        parser.print_help()
    else:
        args.func(args, config)


if __name__ == "__main__":
    import sys

    main(sys.argv[1:])
