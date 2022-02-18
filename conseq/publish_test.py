import pytest
import os

pytestmark = pytest.mark.skipif(
    os.getenv("AWS_ACCESS_KEY_ID") is None,
    reason="requires S3 credentials set as environment variables",
)

TEST_REMOTE_URL_ROOT = "s3://broad-datasci/conseq-test"


def test_publish(tmpdir):
    config = """
        rule a:
            outputs: {"type":"x", "value":"y"}, {"type":"y", "value": "x"}
        rule publish_x:
            inputs: in=all {"type": "x"}
            publish: "{{ TEST_REMOTE_URL_ROOT }}/exp"
            
        let AWS_ACCESS_KEY_ID="{{ AWS_ACCESS_KEY_ID }}"
        let AWS_SECRET_ACCESS_KEY="{{ AWS_SECRET_ACCESS_KEY }}"
        let S3_STAGING_URL="{{ TEST_REMOTE_URL_ROOT }}/staging"
    """

    from .helper import _parse_remote

    storage_api, bucket_name, key_prefix = _parse_remote(TEST_REMOTE_URL_ROOT)
    assert storage_api == "s3"
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")

    dest = key_prefix + "/exp"

    from boto.s3.connection import S3Connection

    c = S3Connection(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    bucket = c.get_bucket(bucket_name)
    key = bucket.get_key(dest)
    if key is not None:
        # if it exists, make sure we delete it and confirm success
        bucket.delete_key(dest)
        key = bucket.get_key(dest)
        assert key is None

    import jinja2

    jinja2_env = jinja2.Environment(undefined=jinja2.StrictUndefined)

    config_file = str(tmpdir.join("t.conseq"))
    with open(config_file, "wt") as fd:
        fd.write(
            jinja2_env.from_string(config).render(
                AWS_ACCESS_KEY_ID=AWS_ACCESS_KEY_ID,
                AWS_SECRET_ACCESS_KEY=AWS_SECRET_ACCESS_KEY,
                TEST_REMOTE_URL_ROOT=TEST_REMOTE_URL_ROOT,
            )
        )

    state_dir = str(tmpdir.join("state"))

    from conseq.main import main

    main(["--dir", state_dir, "run", config_file])

    key = bucket.get_key(dest)
    assert key is not None
