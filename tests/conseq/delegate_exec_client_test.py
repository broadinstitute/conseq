import os
import textwrap
import time
import uuid

import pytest

from conseq import exec_client
import os
import subprocess
from conseq.types import PropsType

pytestmark = pytest.mark.skipif(
    (os.getenv("AWS_ACCESS_KEY_ID") is None)
    or (os.getenv("GOOGLE_APPLICATION_CREDENTIALS") is None),
    reason="requires S3 and google credentials set as environment variables",
)

S3_TEST_REMOTE_URL_ROOT = "s3://broad-datasci/conseq-test"
GS_TEST_REMOTE_URL_ROOT = "gs://broad-achilles-kubeque/conseq-test"
TEST_HELPER_PATH = "python /helper.py"
TEST_RESOURCES = {"mem": 10.0}


@pytest.fixture(scope="session")
def conseq_delegate_test_docker_image_name():
    subprocess.check_call(["bash", "./build.sh"], cwd="conseq-delegate-test")
    return "conseq-delegate-test"


def create_client_for(
    conseq_delegate_test_docker_image_name,
    tmpdir,
    script,
    uid=None,
    remote_url_root=S3_TEST_REMOTE_URL_ROOT,
):
    assert tmpdir is not None

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

    c = exec_client.DelegateExecClient(
        TEST_RESOURCES,
        "delegate",
        workdir,
        remote_url_root,
        remote_url_root + "/CAS",
        TEST_HELPER_PATH,
        f"""docker run --rm -e AWS_ACCESS_KEY_ID={os.getenv('AWS_ACCESS_KEY_ID')} 
           -e AWS_SECRET_ACCESS_KEY={os.getenv('AWS_SECRET_ACCESS_KEY')} 
           -e GOOGLE_APPLICATION_CREDENTIALS=/etc/googlecreds.json
           -v {os.getenv('GOOGLE_APPLICATION_CREDENTIALS')}:/etc/googlecreds.json 
           {conseq_delegate_test_docker_image_name}
           {{COMMAND}}""",
        "python",
        AWS_ACCESS_KEY_ID=None,
        AWS_SECRET_ACCESS_KEY=None,
        recycle_past_runs=False,
    )
    resolver_state = exec_client.RemoteResolveState(scripts_to_download, [])
    return job_dir, c, uid, resolver_state


def create_async_client_for(
    conseq_delegate_test_docker_image_name,
    tmpdir,
    script,
    uid=None,
    remote_url_root=S3_TEST_REMOTE_URL_ROOT,
):
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
    remote_url = remote_url_root + "/" + uid
    cas_remote_url = remote_url + "/CAS"
    helper_path = TEST_HELPER_PATH
    check_cmd_template = 'docker inspect --format="{{{{.State.Running}}}}" {job_id}'
    is_running_pattern = "true"
    terminate_cmd_template = "docker kill {job_id}"
    x_job_id_pattern = "(.*)"
    run_command_template = f"""docker run -d 
        -e AWS_ACCESS_KEY_ID={os.getenv('AWS_ACCESS_KEY_ID')}
        -e AWS_SECRET_ACCESS_KEY={os.getenv('AWS_SECRET_ACCESS_KEY')}
        -e GOOGLE_APPLICATION_CREDENTIALS=/etc/googlecreds.json 
        -v {os.getenv('GOOGLE_APPLICATION_CREDENTIALS')}:/etc/googlecreds.json
        {conseq_delegate_test_docker_image_name}
        {{COMMAND}}"""
    AWS_ACCESS_KEY_ID = None
    AWS_SECRET_ACCESS_KEY = None
    c = exec_client.AsyncDelegateExecClient(
        resources,
        "delegate",
        workdir,
        remote_url,
        cas_remote_url,
        helper_path,
        run_command_template,
        "python",
        AWS_ACCESS_KEY_ID,
        AWS_SECRET_ACCESS_KEY,
        check_cmd_template,
        is_running_pattern,
        terminate_cmd_template,
        x_job_id_pattern,
        False,
    )

    resolver_state = exec_client.RemoteResolveState(scripts_to_download, [])
    return job_dir, c, uid, resolver_state


def _verify_job_runs(job_dir, c, uid, resolver_state):
    print("resolver_state", resolver_state.files_to_upload_and_download)
    e = c.exec_script(
        "name",
        "ID",
        job_dir,
        ["python script1"],
        [{"name": "banana"}],
        True,
        "",
        "desc",
        resolver_state,
        {"mem": 10},
        watch_regex=None,
    )
    while True:
        failure, output = e.get_completion()
        assert failure is None
        if output is not None:
            break
        time.sleep(5)

    assert output == [{"name": "banana"}]


def test_basic_docker_exec(conseq_delegate_test_docker_image_name, tmpdir):
    job_dir, c, uid, resolver_state = create_client_for(
        conseq_delegate_test_docker_image_name,
        tmpdir,
        """
        print("run")
        """,
    )
    _verify_job_runs(job_dir, c, uid, resolver_state)


def test_gs_with_docker_exec(conseq_delegate_test_docker_image_name, tmpdir):
    # try again, but this time using google cloud storage instead of s3
    job_dir, c, uid, resolver_state = create_client_for(
        conseq_delegate_test_docker_image_name,
        tmpdir,
        """
        print("run")
        """,
        remote_url_root=GS_TEST_REMOTE_URL_ROOT,
    )
    _verify_job_runs(job_dir, c, uid, resolver_state)


def test_async_docker_exec(conseq_delegate_test_docker_image_name, tmpdir):
    job_dir, c, uid, resolver_state = create_async_client_for(
        conseq_delegate_test_docker_image_name,
        tmpdir,
        """
        print("run")
        """,
    )
    _verify_job_runs(job_dir, c, uid, resolver_state)


@pytest.mark.parametrize("use_async", [True, False])
def test_delegate_reattach(conseq_delegate_test_docker_image_name, tmpdir, use_async):
    if use_async:
        create_fn = create_async_client_for
    else:
        create_fn = create_client_for

    job_dir, c, uid, resolver_state = create_fn(
        conseq_delegate_test_docker_image_name,
        tmpdir,
        """ 
        print("run")
        """,
    )

    e = c.exec_script(
        "name",
        "ID",
        job_dir,
        ["python script1"],
        [{"name": "test_delegate_reattach"}],
        True,
        "",
        "desc",
        resolver_state,
        {"mem": 10.0},
        watch_regex=None,
    )
    print(e)
    extern_id = e.get_external_id()

    print("external_id=", extern_id)

    _, c2, _, resolver_state = create_fn(
        conseq_delegate_test_docker_image_name, tmpdir, None, uid
    )
    e2 = c2.reattach(extern_id)

    while True:
        result = e2.get_completion()
        assert result.failure_msg is None
        if result.outputs is not None:
            break
        time.sleep(1)

    assert result.outputs == [{"name": "test_delegate_reattach"}]


@pytest.mark.parametrize("use_async", [True, False])
def test_terminate(conseq_delegate_test_docker_image_name, tmpdir, use_async):
    if use_async:
        create_fn = create_async_client_for
    else:
        create_fn = create_client_for

    job_dir, c, uid, resolver_state = create_fn(
        conseq_delegate_test_docker_image_name,
        tmpdir,
        """
        import time
        time.sleep(1000)
        """,
    )

    print("resolver_state", resolver_state.files_to_upload_and_download)
    e = c.exec_script(
        "name",
        "ID",
        job_dir,
        ["python script1"],
        [{"name": "banana"}],
        True,
        "",
        "desc",
        resolver_state,
        {"mem": 10.0},
        watch_regex=None,
    )

    result = e.get_completion()
    assert result.failure_msg is None
    assert result.outputs is None

    e.proc.terminate()
    time.sleep(5)
    result = e.get_completion()
    assert result.failure_msg
    # assert output is not None
