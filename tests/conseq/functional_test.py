# from conseq import parser
import os

from conseq import dep, db
from conseq import depexec


def run_conseq(tmpdir, config, targets=[], assert_clean=True):
    if not os.path.exists(str(tmpdir)):
        os.mkdir(str(tmpdir))

    state_dir = str(tmpdir) + "/state"
    filename = str(tmpdir) + "/t.conseq"
    with open(filename, "wt") as fd:
        fd.write(config)

    print("state_dir=", state_dir)

    db_path = os.path.join(state_dir, "db.sqlite3")
    if assert_clean:
        assert not os.path.exists(db_path)

    depexec.main(
        filename,
        state_dir,
        targets,
        {},
        10,
        False,
        False,
        None,
        remove_unknown_artifacts=True,
    )
    j = dep.open_job_db(db_path)
    return j


def test_rule_with_no_inputs(tmpdir):
    print("test rule with no inputs ------------------------------")
    j = run_conseq(
        tmpdir,
        """
    rule a:
        outputs: {"finished": "true"}
    """,
    )
    assert len(j.find_objs("public", {})) == 1
    print("objs ------------------------------")
    print(j.find_objs("public", {}))


def test_no_results_failure(tmpdir):
    j = run_conseq(
        tmpdir,
        """
    rule a:
        run "bash" with "cat /dev/null"
    """,
    )


def test_rerun_multiple_times(tmpdir):
    j = run_conseq(
        tmpdir,
        """
    rule a:
        outputs: {"finished": "true", "mut":{"$value": "1"}}
    """,
    )
    objs = j.find_objs("public", {})
    assert len(objs) == 1
    assert objs[0]["mut"] == {"$value": "1"}

    # this should result in the object being overwritten because its from a different rule
    j = run_conseq(
        tmpdir,
        """
    rule b:
        outputs: {"finished": "true", "mut":{"$value": "2"}}
    """,
        assert_clean=False,
    )
    objs = j.find_objs("public", {})
    assert len(objs) == 1
    assert objs[0]["mut"] == {"$value": "2"}

    # this should result in the object being overwritten because we forced the rule to execute
    j = run_conseq(
        tmpdir,
        """
    rule b:
        outputs: {"finished": "true", "mut":{"$value": "3"}}
    """,
        targets=["b"],
        assert_clean=False,
    )
    objs = j.find_objs("public", {})
    assert len(objs) == 1
    assert objs[0]["mut"] == {"$value": "3"}


def test_nonzero_retcode(tmpdir):
    j = run_conseq(
        tmpdir,
        """
    rule a:
        run "bash non-existant-file"
    """,
    )


def test_non_key_values(tmpdir):
    j = run_conseq(
        tmpdir,
        """
    rule a:
        outputs: {"finished": "true", "other": {"$value": "apple"}}
        run "bash" with "echo test"
    """,
    )
    assert len(j.find_objs("public", {})) == 1

    j = run_conseq(
        tmpdir,
        """
    rule a:
        outputs: {"finished": "true", "other": {"$value": "apple"}}
        run "bash" with "echo test"
    rule b:
        inputs: in={"finished": "true"}
        outputs: {"name": "result", "filename": {"$filename":"foo.txt"}}
        run "bash" with "echo {{inputs.in.other}} > foo.txt"
    """,
        assert_clean=False,
    )
    results = j.find_objs("public", {"name": "result"})
    assert len(results) == 1
    stdout = open(results[0]["filename"]["$filename"]).read()
    assert "apple\n" == stdout


def assert_transaction_closed():
    if hasattr(db.current_db_cursor_state, "cursor"):
        assert db.current_db_cursor_state.cursor == None


def test_gc(tmpdir):
    print("---------------------gc")
    assert_transaction_closed()

    j = run_conseq(
        tmpdir,
        """
    rule a:
        outputs: {"finished": "true", "other": {"$value": "a"}}
    """,
    )
    print("objs", j.find_objs("public", {}))
    assert len(j.find_objs("public", {})) == 1

    j = run_conseq(
        tmpdir,
        """
    rule b:
        outputs: {"finished": "true", "other": {"$value": "b"}}
    """,
        assert_clean=False,
    )
    print("objs", j.find_objs("public", {}))
    assert len(j.find_objs("public", {})) == 1

    # # make sure we have both executions
    # assert len(j.get_all_executions()) == 2

    j.gc()
    # after GC there's only one
    assert len(j.get_all_executions()) == 1


def test_rules_with_all_exec_once(tmpdir):
    j = run_conseq(
        tmpdir,
        """
    rule a:
        outputs: {"type": "thing", "value": "a"}
    rule b:
        outputs: {"type": "thing", "value": "b"}
    rule c:
        inputs: x=all {"type": "thing"}
        outputs: {"done": "true"}
    """,
    )
    assert len(j.find_objs("public", {})) == 3
    assert len(j.get_all_executions()) == 3


def test_rule_executes_once(tmpdir):
    j = run_conseq(
        tmpdir,
        """
    rule a:
        outputs: {"type": "thing", "value": "a"}
    """,
    )
    assert len(j.find_objs("public", {})) == 1
    assert len(j.get_all_executions()) == 1
    j = run_conseq(
        tmpdir,
        """
    rule a:
        outputs: {"type": "thing", "value": "a"}
    """,
        assert_clean=False,
    )
    assert len(j.find_objs("public", {})) == 1
    assert len(j.get_all_executions()) == 1


def test_regexp_queries(tmpdir):
    j = run_conseq(
        tmpdir,
        """
    rule a:
        outputs: {"type": "thing"}
    rule b:
        inputs: in={"type" ~ "t.*"}
        outputs: {"type": "otherthing"}
    """,
    )
    assert len(j.get_all_executions()) == 2


def test_regexp_query_expands_var(tmpdir):
    j = run_conseq(
        tmpdir,
        """
    let samplevar="thing"
    rule a:
        outputs: {"type": "thing"}
    rule b:
        inputs: in={"type" ~ "{{config.samplevar}}"}
        outputs: {"type": "otherthing"}
    """,
    )
    assert len(j.get_all_executions()) == 2

def test_type_defs(tmpdir):
    j = run_conseq(
        tmpdir,
        """
    type apple = { description: "fruit" }
    """,
    )
    types = j.get_type_defs()
    assert len(types) == 1
    j = run_conseq(
        tmpdir,
        """
    type banana = { description: "fruit too" }
    """,
        assert_clean=False,
    )
    # current policy is to remember all types that have ever been defined. Maybe not a good solution. Re-evalute this later
    types = j.get_type_defs()
    assert len(types) == 2

def test_fileref_copy_to(tmpdir):
    file_a = tmpdir.join("a")
    file_a.write("a")
    file_b = tmpdir.join("b")
    file_b.write("b")

    script = """\"\"\"
        assert open("{{ inputs.a.filename }}").read() == "a"
        assert open("{{ inputs.b.filename }}").read() == "b"
        import os
        cwd = os.path.abspath(".")
        assert os.path.abspath(os.path.dirname("{{ inputs.a.filename }}")) == cwd
        assert os.path.basename("{{ inputs.a.filename }}") == "z"
        assert os.path.abspath(os.path.dirname("{{ inputs.b.filename }}")) != cwd
    \"\"\""""

    j = run_conseq(
        tmpdir,
        """
    rule a:
        inputs: a=filename("{}", copy_to="z"),
                b=filename("{}")
        outputs: {}
        run "python" with {}
    """.format(
            file_a, file_b, "{'done': 'true'}", script
        ),
    )

    execs = j.get_all_executions()
    assert len(execs) == 1
    assert execs[0].status == "completed"


def test_construct_cache_key(tmpdir, monkeypatch):
    blobs = {}

    class MockRemote:
        def __init__(self, remote_url, local_dir, accesskey=None, secretaccesskey=None):
            print("Invoked!!!!")
            self.local_dir = local_dir
            self.remote_url = remote_url

        def exists(self, filename):
            print(f"checking {filename}: {filename in blobs}")
            return filename in blobs

        def upload_str(self, path, blob):
            assert isinstance(blob, str)
            assert path.startswith("gs://banana")
            print(f"putting {path}: {blob}")
            blobs[path] = blob

        def download_as_str(self, path):
            return blobs[path]

    import conseq.helper

    monkeypatch.setattr(conseq.helper, "Remote", MockRemote)

    prolog = """
    let AWS_ACCESS_KEY_ID="x"
    let AWS_SECRET_ACCESS_KEY="y"
    let S3_STAGING_URL="s3://buckey/root"
    let CLOUD_STORAGE_CACHE_ROOT="gs://banana/key"
    """

    # run a job which saves the result in cache
    run_conseq(
        tmpdir.join("repo1"),
        prolog
        + """
    rule a:
        construct-cache-key-run "bash" with '''
            echo '{"a": "val1", "b": "val2"}' > conseq-cache-key.json
        '''
        run 'bash' with '''
        echo '{"outputs": [{"finished": "true"}]}' > results.json
        '''
    """,
    )

    # this job has no knowledge of the previous job, except, it should restore the result from the cache
    j = run_conseq(
        tmpdir.join("repo2"),
        prolog
        + """        
    rule b:
        construct-cache-key-run "bash" with '''
            echo '{"b": "val2", "a": "val1"}' > conseq-cache-key.json
        '''
        run "echo hello"
    """,
    )

    # make sure it got the resulting artifact from the previous run
    artifacts = j.find_objs("public", {})
    assert len(artifacts) == 1
    assert artifacts[0].props == {"finished": "true"}


def test_publish(tmpdir, monkeypatch):
    publish_called = [False]

    def mock_publish_manifest(location, dictionary, config):
        print("dictionary", dictionary)
        assert config is not None
        dictionary = dictionary["in"]
        assert dictionary["finished"] == "true"
        assert dictionary["name"] == "bongo"
        assert dictionary["file"].startswith("s3://")
        assert dictionary["url"] == "s3://foo/key"
        assert location == "manifest-bongo.json"
        publish_called[0] = True

    class MockRemote:
        def __init__(self, remote_url, local_dir, accesskey=None, secretaccesskey=None):
            print("Invoked!!!!")
            self.local_dir = local_dir
            self.remote_url = remote_url

        def exists(self, filename):
            return True
            # print("XXXXXXXX")
            # assert filenames == ["testfile"]
            # return {"testfile": "s3://foo/testfile"}

    import conseq.depexec

    monkeypatch.setattr(conseq.depexec, "publish_manifest", mock_publish_manifest)
    import conseq.helper

    monkeypatch.setattr(conseq.helper, "Remote", MockRemote)

    j = run_conseq(
        tmpdir,
        """
    let AWS_ACCESS_KEY_ID="x"
    let AWS_SECRET_ACCESS_KEY="y"
    let S3_STAGING_URL="s3://buckey/root"
    rule a:
        outputs: {"finished": "true", "name": "bongo", "file": {"$filename": "testfile"}, "url": {"$file_url": "s3://foo/key"}}
        run "bash" with "echo test > testfile"
    rule pub:
        inputs: in={"finished": "true"}
        publish: "manifest-{{ inputs.in.name }}.json"
    """,
    )

    assert publish_called[0]


def test_detect_clobber(tmpdir):
    # if two rules emit the same artifact, the second one should fail. Don't allow a rule to clobber an
    # existing artifact.

    j = run_conseq(
        tmpdir,
        """
    rule a:
        outputs: {"type": "thing"}
    rule b:
        inputs: in={"type": "thing"}
        outputs: {"type": "derived-thing"}
    rule c:
        inputs: in={"type": "thing"}
        outputs: {"type": "derived-thing"}
    """,
    )
    status_by_rule = {x.transform: x.status for x in j.get_all_executions()}
    assert status_by_rule == {"a": "completed", "c": "completed", "b": "failed"}


def test_clobbers_from_rules_with_all_are_okay(tmpdir):
    # if two rules emit the same artifact, the second one should fail. Don't allow a rule to clobber an
    # existing artifact.

    def get_exec_id(j, transform):
        matches = [x.id for x in j.get_all_executions() if x.transform == transform]
        assert len(matches) == 1
        return matches[0]

    j = run_conseq(
        tmpdir,
        """
    rule a:
        outputs: {"type": "thing", "value": "1"}
    rule b:
        inputs: in=all {"type": "thing"}
        outputs: {"type": "derived-thing"}
    """,
    )
    status_by_rule = [f"{x.transform} {x.status}" for x in j.get_all_executions()]
    assert sorted(status_by_rule) == ["a completed", "b completed"]
    orig_b_id = get_exec_id(j, "b")

    j = run_conseq(
        tmpdir,
        """
    rule a:
        outputs: {"type": "thing", "value": "1"}
    rule a2:
        outputs: {"type": "thing", "value": "2"}
    rule b:
        inputs: in=all {"type": "thing"}
        outputs: {"type": "derived-thing"}
    """,
        assert_clean=False,
    )
    b_id = [0]
    status_by_rule = [f"{x.transform} {x.status}" for x in j.get_all_executions()]
    assert sorted(status_by_rule) == ["a completed", "a2 completed", "b completed"]
    new_b_id = get_exec_id(j, "b")

    assert new_b_id != orig_b_id


def test_gc_with_real_cleanup(tmpdir):
    # do an end-to-end simulation of multiple re-runs and doing GC

    config = """
        add-if-missing {"type": "initial", "value": "1"}
        rule a:
            outputs: {"type":"a", "value":"y"}
        rule b:
            inputs: in={"type":"a"}, in2={"type": "initial"}
            outputs: {"type": "b", "value":"1"}
    """
    config_file = str(tmpdir.join("t.conseq"))
    with open(config_file, "wt") as fd:
        fd.write(config)

    state_dir = str(tmpdir.join("state"))

    from conseq.main import main

    # should run two rules, resulting in two directories
    main(["--dir", state_dir, "run", config_file])
    assert os.path.exists(os.path.join(state_dir, "r1"))
    assert os.path.exists(os.path.join(state_dir, "r2"))

    # re-running should do nothing
    main(["--dir", state_dir, "run", config_file])
    assert not os.path.exists(os.path.join(state_dir, "r3"))

    # now change the config and re-run, which should result in one additional directory
    config = """
        add-if-missing {"type": "initial", "value": "2"}
        rule a:
            outputs: {"type":"a", "value":"y"}
        rule b:
            inputs: in={"type":"a"}, in2={"type": "initial"}
            outputs: {"type": "b", "value":"1"}
    """
    with open(config_file, "wt") as fd:
        fd.write(config)
    main(["--dir", state_dir, "run", "--remove-unknown-artifacts", config_file])
    assert os.path.exists(os.path.join(state_dir, "r3"))
    assert not os.path.exists(os.path.join(state_dir, "r4"))

    # running gc should clean up r2 and leave the others
    main(["--dir", state_dir, "gc"])
    assert os.path.exists(os.path.join(state_dir, "r1"))
    assert not os.path.exists(os.path.join(state_dir, "r2"))
    assert os.path.exists(os.path.join(state_dir, "r3"))
    assert not os.path.exists(os.path.join(state_dir, "r4"))


def test_forget(tmpdir):
    config = """
        rule a1:
            outputs: {"type":"a1"}
        rule a2:
            outputs: {"type":"a2"}
    """
    config_file = str(tmpdir.join("t.conseq"))
    with open(config_file, "wt") as fd:
        fd.write(config)

    state_dir = str(tmpdir.join("state"))

    from conseq.main import main

    def was_run(rule_name):
        j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
        return rule_name in [x.transform for x in j.get_all_executions()]

    main(["--dir", state_dir, "run", config_file])
    assert was_run("a1")
    assert was_run("a2")

    main(["--dir", state_dir, "forget", "a1"])
    assert not was_run("a1")
    assert was_run("a2")

    main(["--dir", state_dir, "run", config_file])
    assert was_run("a1")
    assert was_run("a2")

    main(["--dir", state_dir, "forget", ".2", "--regex"])
    assert was_run("a1")
    assert not was_run("a2")

    main(["--dir", state_dir, "run", config_file])
    assert was_run("a1")
    assert was_run("a2")


def test_commands(tmpdir):
    # don't actually test any of the functionality of these commands, only that they execute error free
    # to catch trivial mistakes in setting up parameter passing to these commands

    config = """
        rule a:
            outputs: {"type":"x", "value":"y"}, {"type":"y", "value": "x"}
    """
    config_file = str(tmpdir.join("t.conseq"))
    with open(config_file, "wt") as fd:
        fd.write(config)

    state_dir = str(tmpdir.join("state"))
    html_dir = str(tmpdir.join("html"))

    commands = [
        ["--dir", state_dir, "run", config_file],
        ["--dir", state_dir, "report", html_dir],
        ["--dir", state_dir, "ls"],
        ["--dir", state_dir, "gc"],
        ["--dir", state_dir, "rm", "type=x"],
        ["--dir", state_dir, "rules", config_file],
        ["--dir", state_dir, "debugrun", config_file, "a"],
        ["--dir", state_dir, "history"],
        ["--dir", state_dir, "localize", config_file, "type=x"],
        ["version"],
    ]

    from conseq.main import main

    for command in commands:
        print("running: {}".format(command))
        main(command)