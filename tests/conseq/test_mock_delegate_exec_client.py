import os
import textwrap
import time
import uuid

import pytest

from conseq import exec_client
import os
import subprocess
from conseq.types import PropsType
from conseq.exec_client import NullResolveState, RemoteResolveState


@pytest.fixture(scope="session")
def conseq_delegate_test_docker_image_name():
    subprocess.check_call(["bash", "./build.sh"], cwd="conseq-delegate-test")
    return "conseq-delegate-test"


GS_TEST_REMOTE_URL_ROOT = "gs://broad-achilles-kubeque/conseq-test"
TEST_HELPER_PATH = "python /helper.py"
TEST_RESOURCES = {"mem": 10.0}

from conseq import exec_client
from unittest.mock import MagicMock, create_autospec
import subprocess
from conseq.template import create_jinja2_env, render_template


class MockProc:
    def __init__(self):
        self.pid = 100000000


def test_delegate_exec_client_commands(tmpdir, monkeypatch):
    assert tmpdir is not None
    mock_helper = MagicMock()
    mock_helper.new_remote().remote_url = "fake_remote_url"
    mock_popen = create_autospec(subprocess.Popen)

    def _mock_popen(args, **kwargs):
        # verify that the expansion worked and we're running the right command
        assert args[0] == "bash"
        assert args[1] == "-c"
        assert args[2].startswith("exec docker run --rm image-xyz python /helper.py")
        return MockProc()

    # zee temple of shakyfruit

    mock_popen.side_effect = _mock_popen

    monkeypatch.setattr(exec_client, "helper", mock_helper)
    monkeypatch.setattr(subprocess, "Popen", mock_popen)
    mock_helper.push_to_cas().values.return_value = ["map_name"]
    workdir = str(tmpdir)
    job_dir = workdir + "/r1"
    os.mkdir(job_dir)

    jinja2_env = create_jinja2_env()

    def create_client():
        return exec_client.DelegateExecClient(
            TEST_RESOURCES,
            "delegate",
            workdir,
            GS_TEST_REMOTE_URL_ROOT,
            GS_TEST_REMOTE_URL_ROOT + "/CAS",
            TEST_HELPER_PATH,
            exec_client.TemplatePartial(
                jinja2_env,
                {},
                """docker run --rm {{ parameters.image_name }} {{COMMAND}}""",
            ),
            "python",
            recycle_past_runs=False,
        )

    c1 = create_client()

    execution1 = c1.exec_script(
        name="name",
        id=100,
        job_dir=job_dir,
        run_stmts=["echo hello"],
        outputs=None,
        capture_output=True,
        prologue="",
        desc_name="description",
        resolver_state=RemoteResolveState([], []),
        resources={},
        watch_regex=None,
        executor_parameters={"image_name": "image-xyz"},
    )

    external_id = execution1.get_external_id()

    # make sure reattach works and results in an execution with the same external id (since
    # we can't easily compare executions directly)
    c2 = create_client()
    execution2 = c2.reattach(external_id)

    assert external_id == execution2.get_external_id()
