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

# banana
def _parse_remote(path: str) -> Tuple[str, str, str]:
    m = re.match("^(s3|gs)://([^/]+)/(.*)$", path)
    assert m != None, f"invalid remote path: {path}"
    storage_api = m.group(1)
    bucket_name = m.group(2)
    path = m.group(3)
    return storage_api, bucket_name, path


# def download_s3_as_string(remote):
#     assert remote.startswith("s3:")
#     bucket, remote_path = _parse_remote(remote)

#     key = bucket.get_key(remote_path)
#     if key == None:
#         return None

#     value = key.get_contents_as_string()
#     return value.decode("utf-8")


class StorageConnection:
    def get_bucket(self, bucket_name):
        raise NotImplementedError()

    def exists(self, bucket_name: str, key: str) -> bool:
        raise NotImplementedError()

    def list_keys_with_prefix(self, bucket_name: str, path: str) -> List[str]:
        raise NotImplementedError()

    def set_contents_from_filename(
        self, filename: str, bucket_name: str, path: str, sha256=None
    ):
        raise NotImplementedError()

    def set_contents_from_string(self, bucket_name: str, path: str, text: str):
        raise NotImplementedError()

    def get_contents_as_string(self, bucket_name: str, path: str) -> bytes:
        raise NotImplementedError()

    def get_contents_to_filename(self, bucket_name: str, path: str, dest_path: str):
        raise NotImplementedError()

    def get_sha256(self, bucket_name: str, path: str) -> Optional[str]:
        raise NotImplementedError()

    def get_generation_id(self, bucket_name: str, path: str) -> str:
        raise NotImplementedError()


# .get_metadata("sha256")

from google.cloud import storage


class GSStorageConnection(StorageConnection):
    def __init__(self):
        self.c = storage.Client()

    def exists(self, bucket_name: str, key: str) -> bool:
        return self.c.bucket(bucket_name).get_blob(key) is not None

    def list_keys_with_prefix(self, bucket_name: str, path: str) -> List[str]:
        bucket = self.c.bucket(bucket_name)
        return [x.name for x in self.c.list_blobs(bucket, prefix=path)]

    def get_contents_as_string(self, bucket_name: str, path: str) -> bytes:
        return self.c.bucket(bucket_name).blob(path).download_as_bytes()

    def get_contents_to_filename(self, bucket_name: str, path: str, dest_path: str):
        self.c.bucket(bucket_name).blob(path).download_to_filename(dest_path)

    def get_sha256(self, bucket_name: str, path: str) -> Optional[str]:
        metadata = self.c.bucket(bucket_name).get_blob(path).metadata
        if metadata:
            return metadata.get("sha256")

    def get_generation_id(self, bucket_name: str, path: str) -> str:
        return str(self.c.bucket(bucket_name).get_blob(path).generation)

    def set_contents_from_string(self, bucket_name: str, path: str, text: str):
        self.c.bucket(bucket_name).blob(path).upload_from_string(text)

    def set_contents_from_filename(
        self, filename: str, bucket_name: str, path: str, sha256=None
    ):
        blob = self.c.bucket(bucket_name).blob(path)
        blob.upload_from_filename(filename)

        if sha256:
            blob.metadata = {"sha256": sha256}


class S3StorageConnection(StorageConnection):
    def __init__(self, accesskey, secretaccesskey):
        self.c = S3Connection(accesskey, secretaccesskey)

    def exists(self, bucket_name: str, key: str) -> bool:
        return self.c.get_bucket(bucket_name, validate=False).get_key(key) is not None

    def list_keys_with_prefix(self, bucket_name: str, path: str) -> List[str]:
        bucket = self.c.get_bucket(bucket_name, validate=False)
        return [x.key for x in bucket.list(prefix=path)]

    def get_contents_as_string(self, bucket_name: str, path: str) -> bytes:
        return (
            self.c.get_bucket(bucket_name, validate=False)
            .get_key(path, validate=False)
            .get_contents_as_string()
        )

    def get_contents_to_filename(self, bucket_name: str, path: str, dest_path: str):
        self.c.get_bucket(bucket_name, validate=False).get_key(
            path, validate=False
        ).get_contents_to_filename(dest_path)

    def get_sha256(self, bucket_name: str, path: str) -> Optional[str]:
        return (
            self.c.get_bucket(bucket_name, validate=False)
            .get_key(path)
            .get_metadata("sha256")
        )

    def get_generation_id(self, bucket_name: str, path: str) -> str:
        return self.c.get_bucket(bucket_name, validate=False).get_key(path).etag

    def set_contents_from_string(self, bucket_name: str, path: str, text: str):
        k = self.c.get_bucket(bucket_name, validate=False).get_key(path, validate=False)
        k.set_contents_from_string(text)

    def set_contents_from_filename(
        self, filename: str, bucket_name: str, path: str, sha256=None
    ):
        k = self.c.get_bucket(bucket_name, validate=False).get_key(path, validate=False)
        k.set_contents_from_filename(filename)
        if sha256:
            k.set_metadata("sha256", sha256)


def new_remote(remote_url, local_dir, accesskey, secretaccesskey):
    sc = S3StorageConnection(accesskey, secretaccesskey)
    gs = GSStorageConnection()
    return Remote(remote_url, local_dir, {"s3": sc, "gs": gs})


class Remote:
    def __init__(
        self, remote_url: str, local_dir: str, sc: Dict[str, StorageConnection]
    ):
        assert isinstance(sc, dict)
        self.connections = sc
        self.remote_url = remote_url
        self.local_dir = local_dir
        self.storage_api, self.bucket_name, self.remote_path = _parse_remote(remote_url)

    def _get_conn(self, storage_api: str) -> StorageConnection:
        return self.connections[storage_api]

    def is_full_remote_path(self, path: str):
        return path.startswith("s3:") or path.startswith("gs:")

    def exists(self, remote: str) -> bool:
        storage_api, bucket_name, remote_path = self._normalize_path(remote)

        return self._get_conn(storage_api).exists(bucket_name, remote_path)

    def _download_object(
        self,
        source_storage_api: str,
        source_bucket: str,
        source_key: str,
        dest_path: str,
        stage_dir: str,
        skip_existing: bool,
    ):
        if os.path.exists(dest_path) and skip_existing:
            log.info(
                "Already %s://%s/%s downloaded as %s",
                source_storage_api,
                source_bucket,
                source_key,
                dest_path,
            )
            return

        assert self._get_conn(source_storage_api).exists(source_bucket, source_key)

        def download_to(dest):
            if not os.path.exists(os.path.dirname(dest)):
                os.makedirs(os.path.dirname(dest))
            for i in range(100):
                temp_name = dest + ".in.progress." + str(i)
                if not os.path.exists(temp_name):
                    break

            self._get_conn(source_storage_api).get_contents_to_filename(
                source_bucket, source_key, temp_name
            )
            os.rename(temp_name, dest)

        if stage_dir is not None:
            # if hash is defined for this object, use this for caching
            hash = self._get_conn(source_storage_api).get_sha256(
                source_bucket, source_key
            )
            if hash is not None:
                stage_path = os.path.join(stage_dir, "CAS", hash)
            else:
                # otherwise, fall back to using path and generation ID/etag
                etag = self._get_conn(source_storage_api).get_generation_id(
                    source_bucket, source_key
                )
                stage_path = os.path.join(
                    stage_dir, "gcs", source_bucket, source_key, etag
                )

            download_to(stage_path)

            if not os.path.exists(os.path.dirname(dest_path)):
                os.makedirs(os.path.dirname(dest_path))
            os.link(stage_path, dest_path)
        else:
            download_to(dest_path)

    def download(
        self,
        remote: str,
        local: str,
        ignoreMissing: bool = False,
        skip_existing: bool = True,
        stage_dir: Optional[str] = None,
    ):
        # maybe upload and download should use trailing slash to indicate directory
        # should be uploaded instead of just a file
        if not local.startswith("/"):
            local = os.path.normpath(self.local_dir + "/" + local)

        storage_api, bucket_name, remote_path = self._normalize_path(remote)

        if self._get_conn(storage_api).exists(bucket_name, remote_path):
            # if it's a file, download it
            abs_local = os.path.abspath(local)
            log.info("Downloading file %s to %s", remote_path, abs_local)

            self._download_object(
                storage_api,
                bucket_name,
                remote_path,
                abs_local,
                stage_dir,
                skip_existing=skip_existing,
            )
        else:
            # download everything with the prefix
            transferred = 0
            for key in self._get_conn(storage_api).list_keys_with_prefix(
                bucket_name, remote_path + "/"
            ):
                rest = drop_prefix(remote_path + "/", key)
                if not os.path.exists(local):
                    os.makedirs(local)
                local_path = os.path.join(local, rest)
                log.info(
                    "Downloading dir %s (%s to %s)",
                    remote,
                    os.path.basename(key),
                    local_path,
                )
                self._download_object(
                    storage_api,
                    bucket_name,
                    key,
                    local_path,
                    stage_dir=stage_dir,
                    skip_existing=False,
                )
                transferred += 1

            if transferred == 0 and not ignoreMissing:
                raise Exception("Could not find {}".format(local))

    def upload_to_cas(self, filename: str):
        "upload a single file to CAS"
        mapping = push_to_cas(self, [filename], return_full_url=True)
        paths = list(mapping.values())
        assert len(paths) == 1
        return paths[0]

    def upload(
        self, local: str, remote: str, ignoreMissing=False, force=False, hash=None
    ):
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
                uploaded_url = f"{self.storage_api}://{self.bucket_name}/{remote_path}"
                if not self.exists(remote_path) or force:
                    log.info("Uploading file %s to %s", local, uploaded_url)
                    if hash is None:
                        hash = calc_hash(local_path)
                    self._get_conn(self.storage_api).set_contents_from_filename(
                        local_path, self.bucket_name, remote_path, sha256=hash
                    )
            else:
                # upload everything in the dir
                assert hash is None
                for fn in os.listdir(local_path):
                    full_fn = os.path.join(local_path, fn)
                    if os.path.isfile(full_fn):
                        r = os.path.join(remote_path, fn)
                        if not self.exists(r) or force:
                            log.info("Uploading dir %s (%s to %s)", local_path, fn, fn)
                            hash = calc_hash(local_path)
                            self._get_conn(self.storage_api).set_contents_from_filename(
                                full_fn, self.bucket_name, r, sha256=hash
                            )
                        else:
                            log.info(
                                "Uploading dir %s (%s to %s), skiping existing file",
                                local_path,
                                fn,
                                fn,
                            )
        elif not ignoreMissing:
            raise Exception("Could not find {}".format(local))

        return uploaded_url

    def download_as_str(self, remote: str, timeout: int = 5) -> Optional[str]:
        storage_api, bucket_name, remote_path = self._normalize_path(remote)

        log.debug("downloading as string: %s", remote_path)
        if not self._get_conn(storage_api).exists(bucket_name, remote_path):
            return None

        value = self._get_conn(storage_api).get_contents_as_string(
            bucket_name, remote_path
        )
        return value.decode("utf-8")

    def upload_str(self, remote, text):
        storage_api, bucket_name, remote_path = self._normalize_path(remote)
        log.info(
            "Uploading %s://%s/%s from memory", storage_api, bucket_name, remote_path
        )
        self._get_conn(storage_api).set_contents_from_string(
            bucket_name, remote_path, text
        )

    def _normalize_path(self, remote: str) -> Tuple[str, str, str]:
        if self.is_full_remote_path(remote):
            storage_api, bucket_name, remote_path = _parse_remote(remote)
        else:
            bucket_name = self.bucket_name
            storage_api = self.storage_api
            remote_path = os.path.normpath(self.remote_path + "/" + remote)
        return storage_api, bucket_name, remote_path


def drop_prefix(prefix, value):
    assert value[: len(prefix)] == prefix, "Expected {} to be prefixed with {}".format(
        repr(value), repr(prefix)
    )
    return value[len(prefix) :]


def calc_hash(filename: str) -> str:
    h = hashlib.sha256()
    with open(filename, "rb") as fd:
        for chunk in iter(lambda: fd.read(10000), b""):
            h.update(chunk)
    return h.hexdigest()


def push_str_to_cas(remote, content, filename="<unknown>"):
    h = hashlib.sha256(content.encode("utf-8"))
    hash = h.hexdigest()

    remote_name = "CAS/{}".format(hash)
    if remote.exists(remote_name):
        log.info(
            "Skipping upload of %s because %s already exists", filename, remote_name
        )
    else:
        remote.upload_str(remote_name, content)
    return remote_name


def push_to_cas(
    remote: Remote, filenames: List[str], return_full_url: bool = False
) -> Dict[str, str]:
    "upload multiple files to CAS and return mapping of filename to url"
    name_mapping = {}

    for filename in filenames:
        local_filename = os.path.normpath(os.path.join(remote.local_dir, filename))
        hash = calc_hash(local_filename)
        remote_name = "CAS/{}".format(hash)
        if remote.exists(remote_name):
            log.info(
                "Skipping upload of %s because %s already exists", filename, remote_name
            )
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


# def push_cmd(args, config):
#     remote = Remote(
#         args.remote_url,
#         args.local_dir,
#         config["AWS_ACCESS_KEY_ID"],
#         config["AWS_SECRET_ACCESS_KEY"],
#     )
#     if args.cas:
#         push_to_cas(remote, args.filenames)
#     else:
#         push(remote, args.filenames)


def pull(
    remote, file_mappings, ignoreMissing=False, skip_existing=True, stage_dir=None
):
    log.info("%s files to download", len(file_mappings))
    for remote_path, local_path in file_mappings:
        log.info("downloading %s -> %s", remote_path, local_path)
        remote.download(
            remote_path,
            local_path,
            ignoreMissing=ignoreMissing,
            skip_existing=skip_existing,
            stage_dir=stage_dir,
        )


# def pull_cmd(args, config):
#     remote = Remote(
#         args.remote_url,
#         args.local_dir,
#         config["AWS_ACCESS_KEY_ID"],
#         config["AWS_SECRET_ACCESS_KEY"],
#     )
#     pull(remote, args.file_mappings)


def read_config(filename):
    config = {}
    with open(filename, "rt") as fd:
        for line in fd.readlines():
            m = re.match('\\s*(\\S+)\\s*=\\s*"([^"]+)"', line)
            assert m != None
            config[m.group(1)] = m.group(2)
    return config


def publish_results(results_json_file, remote, published_files_root, results_json_dest):
    if not os.path.exists(results_json_file):
        log.info(
            "Skipping publishing results back. %s does not exist", results_json_file
        )
        return
    with open(results_json_file, encoding="utf8") as fd:
        results = json.load(fd)

    outputs_to_publish = []
    for output in results["outputs"]:
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


def _convert_json_mapping(d):
    result = []
    for rec in d["mapping"]:
        remote = rec["remote"]
        local = rec["local"]
        assert not local.startswith("/")
        result.append((remote, local))
    return result


def _parse_mapping_str(file_mapping):
    assert isinstance(file_mapping, str)
    if ":" in file_mapping:
        remote_path, local_path = file_mapping.split(":")
    else:
        remote_path = local_path = file_mapping
    return (remote_path, local_path)


# def exec_config(args, config):
#     config_content = download_s3_as_string(args.url)
#     if config_content is None:
#         raise Exception("Could not open {}".format(args.url))
#     config = json.loads(config_content)

#     remote = Remote(config["remote_url"], args.local_dir)
#     for r in config["pull"]:
#         remote.download(r["src"], r["dest"])

#     for dirname in config["mkdir"]:
#         if not os.path.exists(dirname):
#             os.makedirs(dirname)

#     # execute command
#     command = config["command"]
#     stdout_path = config["stdout"]
#     stderr_path = config["stderr"]
#     exec_summary_path = config["exec_summary"]
#     try:
#         exec_command_with_capture(
#             command, stderr_path, stdout_path, exec_summary_path, args.local_dir
#         )
#     except Exception:
#         tb = traceback.format_exc()
#         message = "Got exception in exec_command_with_capture():\n" + tb
#         print(
#             "Got an exception and now desperately attempting to gracefully to communicate it back by writing it to the stderr log"
#         )
#         print(message)
#         with open(stderr_path, "at", encoding="utf8") as fd:
#             fd.write(message)

#     # push results
#     for r in config["push"]:
#         remote.upload(r["src"], r["dest"], force=True)


def exec_cmd(args, config):
    remote = new_remote(
        args.remote_url,
        args.local_dir,
        config["AWS_ACCESS_KEY_ID"],
        config["AWS_SECRET_ACCESS_KEY"],
    )
    cas_remote = new_remote(
        args.cas_remote_url,
        args.local_dir,
        config["AWS_ACCESS_KEY_ID"],
        config["AWS_SECRET_ACCESS_KEY"],
    )

    pull_map = []
    if args.download_pull_map is not None:
        dl_pull_map_str = remote.download_as_str(args.download_pull_map)
        pull_map_dict = json.loads(dl_pull_map_str)
        pull_map.extend(_convert_json_mapping(pull_map_dict))

    if args.download is not None:
        for mapping_str in args.download:
            pull_map.append(_parse_mapping_str(mapping_str))

    pull(
        remote,
        pull_map,
        ignoreMissing=True,
        skip_existing=not args.forcedl,
        stage_dir=args.stage_dir,
    )

    exec_command_with_capture(
        args.command, args.stderr, args.stdout, args.retcode, args.local_dir
    )

    if args.upload is not None:
        push(remote, args.upload)

    if args.uploadresults is not None:
        results_json_file = "./results.json"
        published_files_root = args.local_dir
        publish_results(
            results_json_file, cas_remote, published_files_root, args.uploadresults
        )


def exec_command_with_capture(
    command, stderr_path, stdout_path, retcode_path, local_dir
):
    stderr_fd = None
    if stderr_path is not None:
        stderr_fd = os.open(
            os.path.join(local_dir, stderr_path), os.O_WRONLY | os.O_APPEND | os.O_CREAT
        )

    stdout_fd = None
    if stdout_path is not None:
        stdout_fd = os.open(
            os.path.join(local_dir, stdout_path), os.O_WRONLY | os.O_APPEND | os.O_CREAT
        )

    log.info("executing %s", command)
    try:
        retcode = subprocess.call(
            command, stdout=stdout_fd, stderr=stderr_fd, cwd=local_dir
        )
    finally:
        os.close(stdout_fd)
        os.close(stderr_fd)
    log.info("Command returned %s", retcode)

    if retcode_path is not None:
        fd = open(os.path.join(local_dir, retcode_path), "wt")
        state = "success" if retcode == 0 else "failed"
        fd.write(json.dumps({"retcode": retcode, "state": state}))
        fd.close()


def main(varg=None):
    parser = argparse.ArgumentParser("push or pull files from cloud storage")
    parser.add_argument("--config", "-c", help="path to config file")

    subparsers = parser.add_subparsers()

    # push_parser = subparsers.add_parser("push")
    # push_parser.add_argument(
    #     "--cas", help="Use content addressable storage", action="store_true"
    # )
    # push_parser.add_argument("remote_url", help="base remote url to use")
    # push_parser.add_argument("local_dir")
    # push_parser.add_argument("filenames", nargs="+")
    # push_parser.set_defaults(func=push_cmd)

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
    exec_parser.add_argument(
        "--forcedl",
        help="Force download of files even if the destination already exists",
    )
    exec_parser.add_argument(
        "--stage", help="directory to use for staging in local CAS", dest="stage_dir"
    )
    exec_parser.add_argument(
        "--uploadresults",
        help="If set, upload results.json to this location and all other associated files to CAS",
    )
    exec_parser.add_argument("command", nargs=argparse.REMAINDER)
    exec_parser.set_defaults(func=exec_cmd)

    # exec_config_parser = subparsers.add_parser("exec-config")
    # exec_config_parser.add_argument("url")
    # exec_config_parser.add_argument("--local_dir", default=".")
    # exec_config_parser.set_defaults(func=exec_config)

    # pull_parser = subparsers.add_parser("pull")
    # pull_parser.add_argument("remote_url", help="base remote url to pull from")
    # pull_parser.add_argument("local_dir")
    # pull_parser.add_argument(
    #     "file_mappings",
    #     help="mappings of remote paths to local paths of the form 'remote:local'",
    #     nargs="+",
    # )
    # pull_parser.set_defaults(func=pull_cmd)

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
