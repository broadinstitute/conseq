from paramiko.client import SSHClient
import paramiko.config
import tempfile
import os
import sys

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
        print("reading", remote_path)
        tfile = tempfile.NamedTemporaryFile(mode="rt")
        self.get(host, remote_path, tfile.name)
        with open(tfile.name, "rt") as f:
            result = f.read()
        tfile.close()
        return result
    
    def exec_cmd(self, host, command):
        client = self._get_client(host)

        tran = client.get_transport()
        chan = tran.open_session()
        chan.get_pty()
        chan.exec_command(command)
        print("begin Remote output ----------------", command)
        while True:
            buf = chan.recv(10*1024)
            if len(buf) == 0:
                break
            sys.stdout.write(buf.decode("utf-8"))
            sys.stdout.flush()
        print("end remote output --------------------")
        status = chan.recv_exit_status()
        assert status == 0

    def _get_client(self, host):
        if host in self.client_cache:
            client = self.client_cache[host]
        else:
            host_config = self.sshconfig.lookup(host)

            client = SSHClient()
            client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
            client.connect(host_config["hostname"], username=host_config['user'], key_filename=host_config['identityfile'])
            self.client_cache[host] = client
        assert client != None
        return client


