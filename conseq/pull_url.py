import six
from urllib.parse import urlparse
import paramiko
import logging

log = logging.getLogger(__name__)

class Pull:
    def __init__(self):
        self.ssh_client_cache = {}

    def _get_ssh_client(self, host):
        client = paramiko.SSHClient()
        client.load_system_host_keys()
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
        else:
            raise Exception("unrecognized url: {}".format(url))

    def dispose(self):
        for client in self.ssh_client_cache.values():
            client.close()
        self.ssh_client_cache = {}
