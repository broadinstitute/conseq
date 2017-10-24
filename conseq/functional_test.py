#from conseq import parser
from conseq import depexec
from conseq import dep
import os

def run_conseq(tmpdir, config, targets=[], assert_clean=True):
    state_dir=str(tmpdir)+"/state"
    filename = str(tmpdir)+"/t.conseq"
    with open(filename, "wt") as fd:
        fd.write(config)

    print("state_dir=",state_dir)

    db_path = os.path.join(state_dir, "db.sqlite3")
    if assert_clean:
        assert not os.path.exists(db_path)

    depexec.main(filename, state_dir, targets, {}, 10, False, False, None)
    j = dep.open_job_db(db_path)
    return j

def test_rule_with_no_inputs(tmpdir):
    print("test rule with no inputs ------------------------------")
    j = run_conseq(tmpdir, """
    rule a:
        outputs: {"finished": "true"}
    """)
    assert len(j.find_objs("public", {}))==1
    print("objs ------------------------------")
    print(j.find_objs("public", {}))

def test_rule_depending_on_xref(tmpdir):
    j = run_conseq(tmpdir, """
    # pull xfinity page because I'm petty like that
    xref http://www.xfinity.com/ {"name": "webpage"}
    rule a:
        inputs: in={"name": "webpage"}
        outputs: {"finished": "true"}
    """)
    assert len(j.find_objs("public", {}))==2

def test_rule_depending_on_local_xref(tmpdir):
    filename = str(tmpdir)+"/xref_file"
    with open(filename, "w") as fd:
        fd.write("test")

    j = run_conseq(tmpdir, """
    xref """+filename+""" {"name": "testfile"}
    rule a:
        inputs: in={"name": "testfile"}
        outputs: {"finished": "true"}
        run "bash" with "cat {{ inputs.in.filename }}"
    """)
    assert len(j.find_objs("public", {}))==2

def test_no_results_failure(tmpdir):
    j = run_conseq(tmpdir, """
    rule a:
        run "bash" with "cat /dev/null"
    """)

def test_rerun_multiple_times(tmpdir):

    j = run_conseq(tmpdir, """
    rule a:
        outputs: {"finished": "true", "mut":{"$value": "1"}}
    """)
    objs = j.find_objs("public", {})
    assert len(objs)==1
    assert objs[0]["mut"] == {"$value" : "1"}

    # this should result in the object being overwritten because its from a different rule
    j = run_conseq(tmpdir, """
    rule b:
        outputs: {"finished": "true", "mut":{"$value": "2"}}
    """, assert_clean=False)
    objs = j.find_objs("public", {})
    assert len(objs)==1
    assert objs[0]["mut"] == {"$value" : "2"}

    # this should result in the object being overwritten because we forced the rule to execute
    j = run_conseq(tmpdir, """
    rule b:
        outputs: {"finished": "true", "mut":{"$value": "3"}}
    """, targets=["b"], assert_clean=False)
    objs = j.find_objs("public", {})
    assert len(objs)==1
    assert objs[0]["mut"] == {"$value" : "3"}

def test_nonzero_retcode(tmpdir):
    j = run_conseq(tmpdir, """
    rule a:
        run "bash non-existant-file"
    """)

def test_non_key_values(tmpdir):
    j = run_conseq(tmpdir, """
    rule a:
        outputs: {"finished": "true", "other": {"$value": "apple"}}
        run "bash" with "echo test"
    """)
    assert len(j.find_objs("public", {}))==1

    j = run_conseq(tmpdir, """
    rule b:
        inputs: in={"finished": "true"}
        outputs: {"name": "result", "filename": {"$filename":"foo.txt"}}
        run "bash" with "echo {{inputs.in.other}} > foo.txt"
    """, assert_clean=False)
    results = j.find_objs("public", {"name":"result"})
    assert len(results)==1
    stdout = open(results[0]["filename"]["$filename"]).read()
    assert "apple\n" == stdout

def assert_transaction_closed():
    if hasattr(dep.current_db_cursor_state, "cursor"):
        assert dep.current_db_cursor_state.cursor == None

def test_spaces(tmpdir):
    j = run_conseq(tmpdir, """

    rule b:
        inputs: in={"type": "example"}
        outputs: {"type": "derived", "value":"{{inputs.in.value}}"}

    rule a:
        outputs: {"type": "example", "value": "a"}, {"type": "example", "value": "b", "$space": "pocket"}

    """)

    with dep.transaction(j.db):
        spaces = j.objects.get_spaces()
    spaces = list(spaces)
    spaces.sort()

    assert spaces == ['pocket', "public"]

    results = j.find_objs("public", {"type": "example"})
    assert len(results)==1
    results = j.find_objs("public", {"type": "derived"})
    assert len(results)==1
    assert results[0].props["value"] == "a"

    results = j.find_objs("pocket", {"type": "example"})
    assert len(results)==1
    results = j.find_objs("pocket", {"type": "derived"})
    assert len(results)==1
    assert results[0].props["value"] == "b"

def test_gc(tmpdir):
    print("---------------------gc")
    assert_transaction_closed()

    j = run_conseq(tmpdir, """
    rule a:
        outputs: {"finished": "true", "other": {"$value": "a"}}
    """)
    print("objs", j.find_objs("public", {}))
    assert len(j.find_objs("public", {}))==1

    j = run_conseq(tmpdir, """
    rule b:
        outputs: {"finished": "true", "other": {"$value": "b"}}
    """, assert_clean=False)
    print("objs", j.find_objs("public", {}))
    assert len(j.find_objs("public", {}))==1

    # make sure we have both executions
    assert len(j.get_all_executions()) == 2

    j.gc(lambda x: None)
    # after GC there's only one
    assert len(j.get_all_executions()) == 1

def test_rules_with_all_exec_once(tmpdir):
    j = run_conseq(tmpdir, """
    rule a:
        outputs: {"type": "thing", "value": "a"}
    rule b:
        outputs: {"type": "thing", "value": "b"}
    rule c:
        inputs: x=all {"type": "thing"}
        outputs: {"done": "true"}
    """)
    assert len(j.find_objs("public", {})) == 3
    assert len(j.get_all_executions()) == 3

def test_rule_executes_once(tmpdir):
    j = run_conseq(tmpdir, """
    rule a:
        outputs: {"type": "thing", "value": "a"}
    """)
    assert len(j.find_objs("public", {})) == 1
    assert len(j.get_all_executions()) == 1
    j = run_conseq(tmpdir, """
    rule a:
        outputs: {"type": "thing", "value": "a"}
    """, assert_clean=False)
    assert len(j.find_objs("public", {})) == 1
    assert len(j.get_all_executions()) == 1


def test_regexp_queries(tmpdir):
    j = run_conseq(tmpdir, """
    rule a:
        outputs: {"type": "thing"}
    rule b:
        inputs: in={"type" ~ "t.*"}
        outputs: {"type": "otherthing"}
    """)
    assert len(j.get_all_executions()) == 2



def test_rerun_same_result(tmpdir):
    j = run_conseq(tmpdir, """
    rule a:
        outputs: {"type": "thing", "$hash": "1"}
    rule b:
        inputs: in={"type": "thing"}
        outputs: {"type": "otherthing"}
    """)
    assert len(j.get_all_executions()) == 2

    j2 = run_conseq(tmpdir, """
    rule c:
        outputs: {"type": "thing", "$hash": "1"}
    rule b:
        inputs: in={"type": "thing"}
        outputs: {"type": "otherthing"}
    """, assert_clean=False)

    # only "c" should run this time.
    assert len(j2.get_all_executions()) == 3

    j2 = run_conseq(tmpdir, """
    rule d:
        outputs: {"type": "thing", "$hash": "2"}
    rule b:
        inputs: in={"type": "thing"}
        outputs: {"type": "otherthing"}
    """, assert_clean=False)

    # now that the has has changed, d and b should execute
    assert len(j2.get_all_executions()) == 5
    # however, we should only have one instance of "thing"
    assert len(j.find_objs("public", dict(type="thing"))) == 1

def test_publish(tmpdir, monkeypatch):
    publish_called = [False]
    def mock_publish_manifest(location, dictionary, config):
        print("dictionary", dictionary)
        assert config is not None
        dictionary = dictionary['in']
        assert dictionary["finished"] == "true"
        assert dictionary["name"] == "bongo"
        assert "$file_url" in dictionary["file"]
        assert "$file_url" in dictionary["url"]
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

    import conseq.export_cmd
    monkeypatch.setattr(conseq.export_cmd, 'publish_manifest', mock_publish_manifest)
    import conseq.helper
    monkeypatch.setattr(conseq.helper, 'Remote', MockRemote)

    j = run_conseq(tmpdir, """
    let AWS_ACCESS_KEY_ID="x"
    let AWS_SECRET_ACCESS_KEY="y"
    let S3_STAGING_URL="s3://buckey/root"
    rule a:
        outputs: {"finished": "true", "name": "bongo", "file": {"$filename": "testfile"}, "url": {"$file_url": "s3://foo/key"}}
        run "bash" with "echo test > testfile"
    rule pub:
        inputs: in={"finished": "true"}
        publish: "manifest-{{ inputs.in.name }}.json"
    """)

    assert publish_called[0]