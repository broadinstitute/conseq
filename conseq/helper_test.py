import os
from conseq import helper
import uuid

from boto.s3.connection import S3Connection
from boto.s3.key import Key

import pytest
pytestmark = pytest.mark.skipif(os.getenv("AWS_ACCESS_KEY_ID") is None,
                    reason="requires S3 credentials set as environment variables")

def test_exec(tmpdir):
    uid = uuid.uuid4().hex
    bucket = "broad-datasci"
    path = "test/10/"+uid

    url = "s3://"+bucket+"/"+path

    c = S3Connection()
    b = c.get_bucket("broad-datasci")

    k = Key(b)
    k.name = path+"/inputfile"
    k.set_contents_from_string("in")

    local_dir = str(tmpdir)
    helper.main(["exec", "-o", "out.txt", "-e", "err.txt", "-d", ".", "-u", ".", "-r", "retcode",
                 url, local_dir, "bash", "-c", "echo test"])

    assert os.path.exists(local_dir+"/inputfile")

    assert os.path.exists(local_dir+"/out.txt")
    assert os.path.exists(local_dir+"/err.txt")
    assert os.path.exists(local_dir+"/retcode")

    assert b.get_key(path+"/out.txt") != None
    assert b.get_key(path+"/err.txt") != None
    assert b.get_key(path+"/retcode") != None


