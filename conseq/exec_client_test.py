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

TEST_HOST = "datasci-dev"
TEST_REMOTE_PROLOGUE = "source /broad/software/scripts/useuse\n" \
                       "use -q Python-2.7 R-3.2\n"
TEST_SGE_CMD_PROLOGUE = "use -q UGER"
TEST_REMOTE_WORKDIR = "/home/unix/pmontgom/temp_conseq_work"
TEST_REMOTE_URL_ROOT = "s3://broad-datasci/conseq-test"
TEST_HELPER_PATH = "python /home/unix/pmontgom/helper.py"
TEST_RESOURCES = {"mem": 10}

def create_client_for(tmpdir, script, uid=None):
    workdir = str(tmpdir)

    job_dir = workdir+"/1"
    if not os.path.exists(job_dir):
        os.mkdir(job_dir)

    if script is not None:
        with open(workdir+"/1/script1", "wt") as fd:
            fd.write(textwrap.dedent(script))
            fd.close()

    if uid is None:
        uid = uuid.uuid4().hex
    remote_url = TEST_REMOTE_URL_ROOT + "/" + uid
    remote_workdir = TEST_REMOTE_WORKDIR + "/" + uid

    print("remote_workdir=",remote_workdir)

    c = exec_client.SgeExecClient(TEST_HOST, TEST_REMOTE_PROLOGUE, workdir, remote_workdir, remote_url, TEST_HELPER_PATH, TEST_SGE_CMD_PROLOGUE, TEST_RESOURCES)
    resolver_state = exec_client.SGEResolveState([("script1", "script1")],[])
    return job_dir, c, uid, resolver_state

def test_basic_sge_job_exec(tmpdir):
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

def test_sge_job_reattach(tmpdir):
    job_dir, c, uid, resolver_state = create_client_for(tmpdir, """
        print("run")
        """)

    e = c.exec_script("name", "ID", job_dir, ["python script1"], [{"name": "test_sge_job_reattach"}], True, "", "desc", resolver_state, {"mem": 10})
    extern_id = e.get_external_id()

    _, c2, _, resolver_state = create_client_for(tmpdir, None, uid)
    e2 = c2.reattach(extern_id)

    while True:
        failure, output = e2.get_completion()
        assert failure is None
        if output is not None:
            break
        time.sleep(5)

    assert output == [{"name": "test_sge_job_reattach"}]

def test_sge_job_write_file(tmpdir):
    job_dir, c, _, resolver_state = create_client_for(tmpdir, """
        fd = open("output.txt", "wt")
        fd.write("hello")
        fd.close()
        """)

    e = c.exec_script("name", "ID", job_dir, ["python script1"], [{"file": {"$filename": "output.txt"}}], True, "", "desc", resolver_state, {"mem": 10})
    while True:
        failure, output = e.get_completion()
        assert failure is None
        if output is not None:
            break
        time.sleep(5)

    output = output[0]
    assert "file" in output
    assert type(output["file"]) == dict and ("$file_url" in output["file"])

    file_url = output["file"]["$file_url"]
    pull = xref.Pull({"AWS_ACCESS_KEY_ID": os.getenv("AWS_ACCESS_KEY_ID"),
                      "AWS_SECRET_ACCESS_KEY": os.getenv("AWS_SECRET_ACCESS_KEY")})
    local_copy = str(tmpdir)+"/remote_file"
    pull.pull(file_url, local_copy)

    assert open(local_copy, "rt").read() == "hello"


ONE_REMOTE_ONE_LOCAL_CONFIG = '''
let S3_STAGING_URL = "s3://broad-datasci/conseq-test/{{config.RANDSTR}}"

exec-profile sge {
    "type": "sge",
    "SGE_HOST": "sc-master",
    "SGE_CMD_PROLOGUE": "source /etc/profile.d/sge.sh",
    "SGE_PROLOGUE":"""
source /data2/miniconda3/bin/activate /data2/conda/depcon
export AWS_ACCESS_KEY_ID="{{config.AWS_ACCESS_KEY_ID}}"
export AWS_SECRET_ACCESS_KEY="{{config.AWS_SECRET_ACCESS_KEY}}"
""",
    "SGE_REMOTE_WORKDIR": "/data2/conseq_work/{{config.RANDSTR}}",
    "SGE_HELPER_PATH": "/data2/conda/depcon/bin/python /data2/helper.py",
    "resources": { "slots": "100" }
}

#let SGE_HOST="datasci-dev"
#let SGE_PROLOGUE=""
#let SGE_REMOTE_WORKDIR="/home/unix/pmontgom/temp_conseq_work"
#let S3_STAGING_URL="s3://broad-datasci/conseq-test"
#let SGE_HELPER_PATH="python /home/unix/pmontgom/helper.py"

rule a:
    executor: sge
    outputs: {"name":"a", "file":{"$filename": "message"}}
    run "bash" with """
    echo hello > message
    """

rule b:
    executor: sge
    inputs: in={"name": "a"}
    outputs: {"name":"remote", "file":{"$filename": "remote_file"}}
    run "bash" with """
        cat {{ inputs.in.file }} {{ inputs.in.file }} > remote_file
    """

rule c:
    inputs: in={"name":"remote"}
    outputs: {"name":"final", "file":{"$filename": "final"}}
    run "bash" with """
        cp {{ inputs.in.file }} final
    """
'''

from conseq.functional_test import run_conseq

def get_aws_vars():
    return """
    let AWS_ACCESS_KEY_ID = "{}"
    let AWS_SECRET_ACCESS_KEY = "{}"
    let RANDSTR = "{}"
    """.format(os.getenv("AWS_ACCESS_KEY_ID"), os.getenv("AWS_SECRET_ACCESS_KEY"), time.time())

def test_end_to_end(tmpdir):
    s3_config = get_aws_vars()
    j = run_conseq(tmpdir, s3_config + ONE_REMOTE_ONE_LOCAL_CONFIG)

    # verify all outputs generated
    assert len(j.find_objs("public", {}))==3

    # verify the final output is intact
    objs = (j.find_objs("public", {"name": "final"}))
    assert len(objs) == 1
    assert open(objs[0]['file']["$filename"]).read() == "hello\nhello\n"

    # verify that the artfact that went from sge -> sge did not ever get cached locally
    objs = (j.find_objs("public", {"name": "a"}))
    assert len(objs) == 1
    obj = objs[0]
    file_details = list(obj.props["file"].keys())
    assert file_details == ["$file_url"]
