import os
import re
import requests
import hashlib

def to_bool_str(b):
    if b:
        return "True"
    else:
        return "False"

def create_permaname(name):
    permaname = re.sub("['\"]+", "", name.lower())
    permaname = re.sub("[^A-Za-z0-9]+", "-", permaname)
    return permaname


class TaigaClient:
    def __init__(self, url, user_key):
        self.url = url
        self.user_key = user_key
        self.auth_headers = {"Authorization": "Bearer "+user_key}

    def _make_hash(self, filename):
        hash = hashlib.md5()
        with open(filename, "rb") as fd:
            for chunk in iter(lambda: fd.read(4096), b""):
                hash.update(chunk)

        return hash.hexdigest()

    def _update_description(self, dataset_id, description):
        params = dict(name="description", value=description, pk=dataset_id)
        r = requests.post(self.url+"/dataset/update", data=params, headers=self.auth_headers)
        assert r.status_code == 200

    def _handle_existing_versions(self, name, filename):
        hash = self._make_hash(filename)
        previous_version_dsid = None
        already_latest = False

        # if it's okay to overwrite an existing version, first look up the existing version
        dsid = self._get_by_name(name)
        # if there's no existing version, make the API saying this should be a _new_ dataset
        if dsid != None:
            previous_version_dsid = dsid

            # check to see if this file was already uploaded as the latest version
            dsid_with_same_hash = self._get_by_name(name, hash)
            #print("get_by_name(",name, hash,") -> ", dsid_with_same_hash, "prev:", dsid)
            if dsid_with_same_hash == dsid:
                already_latest = True

        return hash, previous_version_dsid, already_latest

    def upload_columnar(self, name, description, is_published, is_public, filename):
        assert description is not None

        hash, previous_version_dsid, already_latest = self._handle_existing_versions(name, filename)
        if already_latest:
            print("Already exists as", previous_version_dsid)
            return previous_version_dsid

        params = dict(name=name, 
            description=description, 
            is_published = to_bool_str(is_published), 
            is_public = to_bool_str(is_public), 
            overwrite_existing = to_bool_str(previous_version_dsid != None),
            permaname = create_permaname(name))

        print("uploading columnar", params)
        files = {'file': open(filename, 'rb')}
        r = requests.post(self.url+"/upload/columnar", files=files, data=params, headers=self.auth_headers)
        assert str(r.status_code)[0] == "3"
        assert not r.url.endswith("/upload/columnar")
        # scrape off the dataset id
        return r.url.split("/")[-1]

    def upload_tabular(self, columns, rows, name, description, is_published, is_public, data_type, format, filename):
        assert description is not None

        hash, previous_version_dsid, already_latest = self._handle_existing_versions(name, filename)
        if already_latest:
            print("Already exists as", previous_version_dsid)
            return previous_version_dsid
        
        params = dict(columns=columns, 
            rows=rows, name=name, 
            description=description, 
            is_published = to_bool_str(is_published), 
            is_public = to_bool_str(is_public), 
            overwrite_existing = to_bool_str(previous_version_dsid != None),
            data_type = data_type, 
            format = format,
            permaname = create_permaname(name))
        print("uploading tabular", params)
        files = {'file': open(filename, 'rb')}
        r = requests.post(self.url+"/upload/tabular", files=files, data=params, headers=self.auth_headers)
        assert str(r.status_code)[0] == "3"
        assert not r.url.endswith("/upload/tabular")
        # scrape off the dataset id
        return r.url.split("/")[-1]

#    def _get_metadata(self, dataset_id):
#        r = requests.get(self.url+"/rest/v0/metadata/"+dataset_id)
#        return r.json()

    def _get_by_name(self, name, md5=None):
        params = dict(fetch="id", name=create_permaname(name))
        if md5 != None:
            params['md5'] = md5
        r = requests.get(self.url+"/rest/v0/namedDataset", params=params)
        if r.status_code == 404:
            return None
        return r.text

########################################

def compute_md5(filename, extra=None):
    hash = hashlib.md5()
    with open(filename, "rb") as fd:
        for chunk in iter(lambda: fd.read(4096), b""):
            hash.update(chunk)
    if extra != None:
        hash.update(extra)

    return hash.hexdigest()

import tempfile
import subprocess

def execute_r(script_body):
    fd = tempfile.NamedTemporaryFile(mode="wt")
    fd.write(script_body)
    fd.flush()

    subprocess.check_call(["Rscript", fd.name])
    fd.close()

def convert_columnar(filename, dest):
    script = """
        data <- read.table("{filename}", check.names=F, sep="\t")
        save(data, filename="{dest}")
    """.format(**locals())
    execute_r(script)

def convert_tabular(filename, dest, format):
    if format == "gct":
        load_script = """data <- read.table("{filename}", skip=2, sep="\t", head=T, row.names=1) ; stopifnot(names(data)[1] == "Description") ;  data <- data[,-1] ; data <- as.matrix(data) """
    elif format == "csv":
        load_script = """ data <- read.table("{filename}", check.names=F, row.names=1, head=T, sep=",") """
    elif format == "tsv":
        load_script = """ data <- read.table("{filename}", check.names=F, row.names=1, head=T, sep="\t") """
    else:
        raise Exception("unknown format {}".format(format))

    script = (load_script + "\nsave(data, filename=\"{dest}\")\n").format(**locals())

    execute_r(script)

class MockClient:
    def __init__(self):
        pass

    def upload_columnar(self, name, description, is_published, is_public, filename):
        hash = compute_md5(filename)
        dsid = "local-"+hash
        dest = os.path.join(os.path.expanduser("~/.taiga"), dsid+".Rdata")

        if os.path.exists(dest):
            print("Already exists as", dsid)
            return dsid

        convert_columnar(filename, dest)

        return dsid

    def upload_tabular(self, columns, rows, name, description, is_published, is_public, data_type, format, filename):
        hash = compute_md5(filename, extra=format.encode("utf-8"))
        dsid = "local-"+hash
        dest = os.path.join(os.path.expanduser("~/.taiga"), dsid+".Rdata")

        if os.path.exists(dest):
            print("Already exists as", dsid)
            return dsid

        convert_tabular(filename, dest, format)

        return dsid
