import time
import textwrap
import uuid
import os
import logging
from conseq import xref

import pytest
pytestmark = pytest.mark.skipif(os.getenv("AWS_ACCESS_KEY_ID") is None,
                    reason="requires S3 credentials set as environment variables")

from conseq import exec_client
import os

TEST_REMOTE_URL_ROOT = "s3://broad-datasci/conseq-test"
TEST_HELPER_PATH = "python /helper.py"
TEST_RESOURCES = {"mem": 10}

def create_client_for(tmpdir, script, uid=None):
    workdir = str(tmpdir)

    job_dir = workdir+"/r1"
    if not os.path.exists(job_dir):
        os.mkdir(job_dir)

    scripts_to_download = []
    if script is not None:
        scripts_to_download.append( (workdir+"/r1/script1", "script1"))
        with open(workdir+"/r1/script1", "wt") as fd:
            fd.write(textwrap.dedent(script))
            fd.close()

    if uid is None:
        uid = uuid.uuid4().hex
    #remote_url = TEST_REMOTE_URL_ROOT + "/" + uid

    c = exec_client.DelegateExecClient(TEST_RESOURCES, workdir, TEST_REMOTE_URL_ROOT, TEST_REMOTE_URL_ROOT+"/CAS", TEST_HELPER_PATH,
                                       "docker run --rm -e AWS_ACCESS_KEY_ID="+os.getenv("AWS_ACCESS_KEY_ID")+
                                       " -e AWS_SECRET_ACCESS_KEY="+os.getenv("AWS_SECRET_ACCESS_KEY")+
                                       " conseq-del-test {COMMAND}",
                                       "python",
                                       AWS_ACCESS_KEY_ID=None, AWS_SECRET_ACCESS_KEY=None)
    resolver_state = exec_client.SGEResolveState(scripts_to_download,[])
    return job_dir, c, uid, resolver_state

def test_basic_docker_exec(tmpdir):
    job_dir, c, uid, resolver_state = create_client_for(tmpdir, """
        print("run")
        """)

    print("resolver_state", resolver_state.files_to_upload_and_download)
    e = c.exec_script("name", "ID", job_dir, ["python script1"], [{"name": "banana"}], True, "", "desc", resolver_state, {"mem": 10})
    while True:
        failure, output = e.get_completion()
        assert failure is None
        if output is not None:
            break
        time.sleep(5)

    assert output == [{"name": "banana"}]


def test_delegate_reattach(tmpdir):
    job_dir, c, uid, resolver_state = create_client_for(tmpdir, """
        print("run")
        """)

    e = c.exec_script("name", "ID", job_dir, ["python script1"], [{"name": "test_delegate_reattach"}], True, "", "desc", resolver_state, {"mem": 10})
    extern_id = e.get_external_id()

    print("external_id=", extern_id)

    _, c2, _, resolver_state = create_client_for(tmpdir, None, uid)
    e2 = c2.reattach(extern_id)

    while True:
        failure, output = e2.get_completion()
        assert failure is None
        if output is not None:
            break
        time.sleep(1)

    assert output == [{"name": "test_delegate_reattach"}]
