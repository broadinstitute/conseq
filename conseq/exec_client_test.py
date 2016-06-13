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
TEST_PROLOGUE = "use UGER"
TEST_REMOTE_WORKDIR = "/home/unix/pmontgom/temp_conseq_work"
TEST_REMOTE_URL_ROOT = "s3://broad-datasci/conseq-test"
TEST_HELPER_PATH = "python /home/unix/pmontgom/helper.py"

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

    c = exec_client.SgeExecClient(TEST_HOST, TEST_PROLOGUE, workdir, remote_workdir, remote_url, TEST_HELPER_PATH)
    resolver_state = exec_client.SGEResolveState([("script1", "script1")],[])
    return job_dir, c, uid, resolver_state

def test_basic_sge_job_exec(tmpdir):
    job_dir, c, uid, resolver_state = create_client_for(tmpdir, """
        print("run")
        """)

    e = c.exec_script("name", "ID", job_dir, ["python script1"], [{"name": "banana"}], True, "", "desc", resolver_state)
    while True:
        failure, output = e.get_completion()
        assert failure is None
        if output is not None:
            break
        time.sleep(5)

    assert output == [{"name": "banana"}]

def test_sge_job_reattach(tmpdir):
    job_dir, c, uid = create_client_for(tmpdir, """
        print("run")
        """)

    e = c.exec_script("name", "ID", job_dir, ["python script1"], [{"name": "test_sge_job_reattach"}], True, "", "desc", exec_client.SGEResolveState([],[]))
    extern_id = e.get_external_id()

    _, c2, _ = create_client_for(tmpdir, None, uid)
    e2 = c2.reattach(extern_id)

    while True:
        failure, output = e2.get_completion()
        assert failure is None
        if output is not None:
            break
        time.sleep(5)

    assert output == [{"name": "test_sge_job_reattach"}]

def test_sge_job_write_file(tmpdir):
    job_dir, c, _ = create_client_for(tmpdir, """
        fd = open("output.txt", "wt")
        fd.write("hello")
        fd.close()
        """)

    e = c.exec_script("name", "ID", job_dir, ["python script1"], [{"file": {"$filename": "output.txt"}}], True, "", "desc", exec_client.SGEResolveState([],[]))
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
let SGE_HOST="datasci-dev"
let SGE_PROLOGUE=""
let SGE_REMOTE_WORKDIR="/home/unix/pmontgom/temp_conseq_work"
let S3_STAGING_URL="s3://broad-datasci/conseq-test"
let SGE_HELPER_PATH="python /home/unix/pmontgom/helper.py"

rule a:
    options: sge
    outputs: {"name":"a", "file":{"$filename": "message"}}
    run "bash" with """
    echo hello > message
    """


rule b:
    inputs: in={"name": "a"}
    outputs: {"name":"final", "file":{"$filename": "final"}}
    run "bash" with """
        cat {{ inputs.in.file }} {{ inputs.in.file }} > final
    """
'''

from conseq.functional_test import run_conseq

def get_aws_vars() :
    return """
    let AWS_ACCESS_KEY_ID = "{}"
    let AWS_SECRET_ACCESS_KEY = "{}"
    """.format(os.getenv("AWS_ACCESS_KEY_ID"), os.getenv("AWS_SECRET_ACCESS_KEY"))

def test_end_to_end(tmpdir):
    s3_config = get_aws_vars()
    j = run_conseq(tmpdir, s3_config + ONE_REMOTE_ONE_LOCAL_CONFIG)
    assert len(j.find_objs("public", {}))==2
    objs = (j.find_objs("public", {"name": "final"}))
    assert len(objs) == 1
    assert open(objs[0]['file']["$filename"]).read() == "hello\nhello\n"


SIMPLE_FLOCK_JOB = '''
let SGE_HOST="datasci-dev"
let SGE_PROLOGUE=""
let SGE_REMOTE_WORKDIR="/home/unix/pmontgom/temp_conseq_work"
let S3_STAGING_URL="s3://broad-datasci/conseq-test"
let SGE_HELPER_PATH="python /home/unix/pmontgom/helper.py"

rule a:
    submit-r-flock "a" """
        a.scatter <- function() {
          list(inputs=seq(3), shared=NULL)
        }
        a.map <- function(input, shared) {
          return(input*2)
        }
        a.gather <- function(files, shared) {
          values <- sapply(files, function(fn) { readRDS(fn) } )
          writeLines(as.character(values), "results/final.txt")
          writeLines("{"outputs": [{"name": "final", "file": {"$filename": "results/final.txt"}}]}", "results/results.json")
        }
    """
'''

def test_flockish(tmpdir):
    j = run_conseq(tmpdir, get_aws_vars() + SIMPLE_FLOCK_JOB)
    objs = j.find_objs("public", {})
    assert len(objs)==1
    assert open(objs[0]['file']["$filename"]).read() == "2\n4\n6"
