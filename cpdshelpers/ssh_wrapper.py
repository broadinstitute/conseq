from paramiko.client import SSHClient
import paramiko.config
import tempfile
import os
import sys
from io import StringIO
import getpass

import logging
import socket

log = logging.getLogger(__name__)

class SimpleSSH:
    def __init__(self):
        sshconfig = paramiko.config.SSHConfig()
        config_name = os.path.expanduser("~/.ssh/config")
        sshconfig.parse(open(config_name))

        self.sshconfig = sshconfig
        self.client_cache = {}

    def put(self, host, local_path, dest_path):
        client = self._get_client(host)
        
        sftp = client.open_sftp()
        sftp.put(local_path, dest_path)

    def put_string(self, host, body, dest_path):
        tfile = tempfile.NamedTemporaryFile(mode="wt")
        tfile.write(body)
        tfile.flush()
        self.put(host, tfile.name, dest_path)
        tfile.close()

    def get(self, host, remote_path, local_path):
        client = self._get_client(host)
        
        sftp = client.open_sftp()
        sftp.get(remote_path, local_path)

    def get_as_string(self, host, remote_path):
        log.info("reading %s", remote_path)
        tfile = tempfile.NamedTemporaryFile(mode="rt")
        self.get(host, remote_path, tfile.name)
        with open(tfile.name, "rt") as f:
            result = f.read()
        tfile.close()
        return result
    
    def file_exists(self, host, remote_path):
        client = self._get_client(host)
        sftp = client.open_sftp()
        try: 
            s = sftp.stat(remote_path)
            return True
        except FileNotFoundError:
            return False

    def exec_cmd(self, host, command, echo=False, assert_success=True, logger=None):
        if logger is None:
            logger = log.info
        logger("%s: executing %s", host, command)

        captured_stdout = StringIO()

        client = self._get_client(host)

        tran = client.get_transport()
        chan = tran.open_session()
        chan.get_pty()
        chan.exec_command(command)
        while True:
            buf = chan.recv(10*1024)
            if len(buf) == 0:
                break
            # sys.stdout.write(buf.decode("utf-8"))
            # sys.stdout.flush()
            captured_stdout.write(buf.decode("utf-8"))
        status = chan.recv_exit_status()
        if assert_success:
            assert status == 0, "status={}, captured_stdout={}".format(status, captured_stdout.getvalue())

        return captured_stdout.getvalue()

    def _get_client(self, host, timeout=1, connect_attempts=5):
        if host in self.client_cache:
            client = self.client_cache[host]
        else:
            host_config = self.sshconfig.lookup(host)

            client = SSHClient()
            client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
            username = getpass.getuser()
            if 'user' in host_config:
                username = host_config['user']
            key_filename = os.path.expanduser("~/.ssh/id_rsa")
            if 'identityfile' in host_config:
                key_filename = host_config['identityfile']

            successful_connect = False
            for attempts in range(connect_attempts):
                try:
                    client.connect(host_config["hostname"], username=username, key_filename=key_filename, timeout=timeout)
                    successful_connect = True
                    break
                except socket.timeout:
                    pass

            if not successful_connect:
                raise Exception("Connect to {} failed with timeout for {} attempts".format(host_config["hostname"], connect_attempts))

            self.client_cache[host] = client
        assert client != None
        return client


