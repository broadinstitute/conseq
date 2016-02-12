import six
from urllib.parse import urlparse
import paramiko
import logging
import os

log = logging.getLogger(__name__)

import urllib

def http_fetch(url, dest):
    with open(dest, "wb") as fdo:
        fd = urllib.request.urlopen(url)
        for chunk in iter(lambda: fd.read(10000), b""):
            fdo.write(chunk)

class Pull:
    def __init__(self):
        self.ssh_client_cache = {}

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
        elif parts.scheme in ["http", "https"]:
            http_fetch(url, dest_path)
        else:
            raise Exception("unrecognized url: {}, {}".format(url, parts))

    def dispose(self):
        for client in self.ssh_client_cache.values():
            client.close()
        self.ssh_client_cache = {}
