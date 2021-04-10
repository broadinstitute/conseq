import os
import textwrap
import time
import uuid

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

    job_dir = workdir + "/r1"
    if not os.path.exists(job_dir):
        os.mkdir(job_dir)

    scripts_to_download = []
    if script is not None:
        scripts_to_download.append((workdir + "/r1/script1", "script1"))
        with open(workdir + "/r1/script1", "wt") as fd:
            fd.write(textwrap.dedent(script))
            fd.close()

    if uid is None:
        uid = uuid.uuid4().hex
    # remote_url = TEST_REMOTE_URL_ROOT + "/" + uid

    c = exec_client.DelegateExecClient(TEST_RESOURCES, "delegate", workdir, TEST_REMOTE_URL_ROOT,
                                       TEST_REMOTE_URL_ROOT + "/CAS", TEST_HELPER_PATH,
                                       "docker run --rm -e AWS_ACCESS_KEY_ID=" + os.getenv("AWS_ACCESS_KEY_ID") +
                                       " -e AWS_SECRET_ACCESS_KEY=" + os.getenv("AWS_SECRET_ACCESS_KEY") +
                                       " conseq-delegate-test {COMMAND}",
                                       "python",
                                       AWS_ACCESS_KEY_ID=None, AWS_SECRET_ACCESS_KEY=None,
                                       recycle_past_runs=False)
    resolver_state = exec_client.RemoteResolveState(scripts_to_download, [])
    return job_dir, c, uid, resolver_state


def create_async_client_for(tmpdir, script, uid=None):
    workdir = str(tmpdir)

    job_dir = workdir + "/r1"
    if not os.path.exists(job_dir):
        os.mkdir(job_dir)

    scripts_to_download = []
    if script is not None:
        scripts_to_download.append((workdir + "/r1/script1", "script1"))
        with open(workdir + "/r1/script1", "wt") as fd:
            fd.write(textwrap.dedent(script))
            fd.close()

    if uid is None:
        uid = uuid.uuid4().hex

    resources = TEST_RESOURCES
    remote_url = TEST_REMOTE_URL_ROOT + "/" + uid
    cas_remote_url = remote_url + "/CAS"
    helper_path = TEST_HELPER_PATH
    check_cmd_template = "docker inspect --format=\"{{{{.State.Running}}}}\" {job_id}"
    is_running_pattern = "true"
    terminate_cmd_template = "docker kill {job_id}"
    x_job_id_pattern = "(.*)"
    run_command_template = ("docker run -d -e AWS_ACCESS_KEY_ID=" + os.getenv("AWS_ACCESS_KEY_ID") +
                            " -e AWS_SECRET_ACCESS_KEY=" + os.getenv("AWS_SECRET_ACCESS_KEY") +
                            " conseq-delegate-test {COMMAND}")
    AWS_ACCESS_KEY_ID = None
    AWS_SECRET_ACCESS_KEY = None
    c = exec_client.AsyncDelegateExecClient(resources, "delegate", workdir, remote_url, cas_remote_url,
                                            helper_path,
                                            run_command_template,
                                            "python",
                                            AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY,
                                            check_cmd_template, is_running_pattern, terminate_cmd_template,
                                            x_job_id_pattern,
                                            False)

    resolver_state = exec_client.RemoteResolveState(scripts_to_download, [])
    return job_dir, c, uid, resolver_state



def _verify_job_runs(job_dir, c, uid, resolver_state):
    print("resolver_state", resolver_state.files_to_upload_and_download)
    e = c.exec_script("name", "ID", job_dir, ["python script1"], [{"name": "banana"}], True, "", "desc", resolver_state,
                      {"mem": 10}, watch_regex=None)
    while True:
        failure, output = e.get_completion()
        assert failure is None
        if output is not None:
            break
        time.sleep(5)

    assert output == [{"name": "banana"}]


def test_basic_docker_exec(tmpdir):
    job_dir, c, uid, resolver_state = create_client_for(tmpdir, """
        print("run")
        """)
    _verify_job_runs(job_dir, c, uid, resolver_state)


def test_async_docker_exec(tmpdir):
    job_dir, c, uid, resolver_state = create_async_client_for(tmpdir, """
        print("run")
        """)
    _verify_job_runs(job_dir, c, uid, resolver_state)


@pytest.mark.parametrize("use_async", [True, False])
def test_delegate_reattach(tmpdir, use_async):
    if use_async:
        create_fn = create_async_client_for
    else:
        create_fn = create_client_for

    job_dir, c, uid, resolver_state = create_fn(tmpdir, """
        print("run")
        """)

    e = c.exec_script("name", "ID", job_dir, ["python script1"], [{"name": "test_delegate_reattach"}], True, "", "desc",
                      resolver_state, {"mem": 10}, watch_regex=None)
    print(e)
    extern_id = e.get_external_id()

    print("external_id=", extern_id)

    _, c2, _, resolver_state = create_fn(tmpdir, None, uid)
    e2 = c2.reattach(extern_id)

    while True:
        failure, output = e2.get_completion()
        assert failure is None
        if output is not None:
            break
        time.sleep(1)

    assert output == [{"name": "test_delegate_reattach"}]


@pytest.mark.parametrize("use_async", [True, False])
def test_terminate(tmpdir, use_async):
    if use_async:
        create_fn = create_async_client_for
    else:
        create_fn = create_client_for

    job_dir, c, uid, resolver_state = create_fn(tmpdir, """
        import time
        time.sleep(1000)
        """)

    print("resolver_state", resolver_state.files_to_upload_and_download)
    e = c.exec_script("name", "ID", job_dir, ["python script1"], [{"name": "banana"}], True, "", "desc", resolver_state,
                      {"mem": 10}, watch_regex=None)

    failure, output = e.get_completion()
    assert failure is None
    assert output is None

    e.proc.terminate()
    time.sleep(5)
    failure, output = e.get_completion()
    assert failure
    # assert output is not None
