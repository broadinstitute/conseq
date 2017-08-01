import os
import tempfile
from six.moves.urllib.parse import urlparse
from six.moves.urllib import request

import paramiko
import logging
import os

log = logging.getLogger(__name__)

def http_fetch(url, dest):
    with open(dest, "wb") as fdo:
        fd = request.urlopen(url)
        for chunk in iter(lambda: fd.read(10000), b""):
            fdo.write(chunk)

from boto.s3.connection import S3Connection
from conseq.patched_resumable_download_handler import ResumableDownloadHandler

def s3_fetch(bucket_name, path, destination_filename, config):
    # retry_count = 0
    # max_retries = 10
    #
    # while True:
    #     c = S3Connection(config["AWS_ACCESS_KEY_ID"], config["AWS_SECRET_ACCESS_KEY"])
    #     bucket = c.get_bucket(bucket_name)
    #     k = Key(bucket)
    #     k.key = path
    #     res_download_handler = ResumableDownloadHandler(num_retries=5)
    #
    #     try:
    #         k.get_contents_to_filename(destination_filename, res_download_handler=res_download_handler)
    #         break
    #     except socket.timeout:
    #         if retry_count >= max_retries:
    #             log.error("Too many retries.  Aborting")
    #             raise
    #         retry_count += 1
    #         log.warn("Timeout while fetching s3://{}/{}, retrying...".format(bucket_name, path))
    #

    c = S3Connection(config["AWS_ACCESS_KEY_ID"], config["AWS_SECRET_ACCESS_KEY"])
    bucket = c.get_bucket(bucket_name)
    k = bucket.get_key(path)
    res_download_handler = ResumableDownloadHandler(num_retries=5)

    last = [time.time()]
    def report_progress(bytes_done, total_expected):
        now = time.time()
        elapsed = last[0] - now
        if elapsed > 10:
            log.info("Downloaded {}/{} ({})".format(bytes_done, total_expected, 100*bytes_done/total_expected))

    k.get_contents_to_filename(destination_filename, res_download_handler=res_download_handler, cb=report_progress)


class Pull:
    def __init__(self, config):
        self.ssh_client_cache = {}
        self.config = config

    def _get_ssh_client(self, host):
        client = paramiko.SSHClient()
        #client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())

        sshconfig = paramiko.config.SSHConfig()
        config_name = os.path.expanduser("~/.ssh/config")
        sshconfig.parse(open(config_name))
        host_config = sshconfig.lookup(host)
        if host_config != None:
            client.connect(host_config["hostname"], username=host_config['user'], key_filename=host_config['identityfile'])
        else:
            client.connect(host)

        self.ssh_client_cache[host] = client
        return client

    def pull(self, url, dest_path):
        log.warn("Downloading {} -> {}".format(url, dest_path))

        parts = urlparse(url)
        if parts.scheme == "ssh":
            client = self._get_ssh_client(parts.netloc)
            transport = client.get_transport()
            sftp = transport.open_sftp_client()
            sftp.get(parts.path, dest_path)
        elif parts.scheme in ["s3"]:
            s3_fetch(parts.netloc, parts.path, dest_path, self.config)
        elif parts.scheme in ["http", "https"]:
            http_fetch(url, dest_path)
        else:
            raise Exception("unrecognized url: {}, {}".format(url, parts))
        return "invalid"

    def dispose(self):
        for client in self.ssh_client_cache.values():
            client.close()
        self.ssh_client_cache = {}

import time
import sqlite3
def open_cache_db(state_dir):
    filename = os.path.join(state_dir, "cache.sqlite3")
    needs_create = not os.path.exists(filename)

    db = sqlite3.connect(filename)

    stmts = []
    if needs_create:
        stmts.extend([
            "create table downloaded (url string PRIMARY KEY, filename string, etag string, fetched_time integer)",
            "create table settings (schema_version integer)",
            "insert into settings (schema_version) values (1)",
        ])

    for stmt in stmts:
        db.execute(stmt)

    return DownloadCacheDb(db)

class DownloadCacheDb:
    def __init__(self, db):
        self.db = db

    def put(self, url, filename, etag, fetched_time):
        c = self.db.cursor()
        try:
            c.execute("insert into downloaded (url, filename, etag, fetched_time) values (?, ?, ?, ?)", [url, filename, etag, fetched_time])
            self.db.commit()
        finally:
            c.close()

    def get(self, url):
        c = self.db.cursor()
        try:
            c.execute("select filename, etag, fetched_time from downloaded where url = ?", [url])
            result = c.fetchone()
        finally:
            c.close()
        return result

class Resolver:
    def __init__(self, state_dir, config):
        self.puller = Pull(config)
        self.config = config
        self.cache = open_cache_db(state_dir)

    def resolve(self, url):
        if os.path.exists(url):
            return dict(filename=os.path.abspath(url))
        elif url.startswith("taiga://"):
            from conseq import taiga_pull
            dataset_id = url.replace("taiga://", "")
            return dict(dataset_id = dataset_id)
        else:
            url_rec = self.cache.get(url)
            dest_filename = None
            if url_rec is not None:
                dest_filename, etag, _ = url_rec
                # double check the file still exists
                if not os.path.exists(dest_filename):
                    dest_filename = None
                    self.cache.evict(url)

            if dest_filename is None:
                dest_filename = tempfile.NamedTemporaryFile(delete=False, dir=self.config["DL_CACHE_DIR"]).name
                etag = self.puller.pull(url, dest_filename)
                self.cache.put(url, dest_filename, etag, time.time())

            return dict(filename=dest_filename, etag=etag)

    def is_stale(self, url, obj):
        if os.path.exists(url):
            return False
        elif url.startswith("taiga://"):
            dataset_id = url.replace("taiga://", "")
            return obj["dataset_id"]["$value"] == dataset_id
        else:
            etag = self.puller.get_etag(url)
            return etag != obj["etag"]["$value"]


