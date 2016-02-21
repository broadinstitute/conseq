from . import parser
from . import depexec
from . import dep
import os

def run_conseq(tmpdir, config, targets=[]):
    state_dir=str(tmpdir)+"/state"
    filename = str(tmpdir)+"/t.conseq"
    with open(filename, "wt") as fd:
        fd.write(config)
    depexec.main(filename, state_dir, targets, {}, 10)
    j = dep.open_job_db(os.path.join(state_dir, "db.sqlite3"))
    return j

def test_rule_with_no_inputs(tmpdir):
    print("test rule with no inputs ------------------------------")
    j = run_conseq(tmpdir, """
    rule a:
        outputs: {"finished": "true"}
        run "bash" with "echo test"
    """)
    assert len(j.find_objs({}))==1
    print("objs ------------------------------")
    print(j.find_objs({}))

def test_rule_depending_on_xref(tmpdir):
    j = run_conseq(tmpdir, """
    # pull xfinity page because I'm petty like that
    xref http://www.xfinity.com/ {"name": "webpage"}
    rule a:
        inputs: in={"name": "webpage"}
        outputs: {"finished": "true"}
        run "bash" with "echo test"
    """)
    assert len(j.find_objs({}))==2

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
    assert len(j.find_objs({}))==2

def test_no_results_failure(tmpdir):
    j = run_conseq(tmpdir, """
    rule a:
        run "bash" with "cat /dev/null"
    """)

def test_rerun_multiple_times(tmpdir):

    j = run_conseq(tmpdir, """
    rule a:
        outputs: {"finished": "true", "mut":{"$value": "1"}}
        run "bash -c echo test"
    """)
    objs = j.find_objs({})
    assert len(objs)==1
    assert objs[0]["mut"] == {"$value" : "1"}

    # this should result in the object being overwritten because its from a different rule
    j = run_conseq(tmpdir, """
    rule b:
        outputs: {"finished": "true", "mut":{"$value": "2"}}
        run "bash -c echo test"
    """)
    objs = j.find_objs({})
    assert len(objs)==1
    assert objs[0]["mut"] == {"$value" : "2"}

    # this should result in the object being overwritten because we forced the rule to execute
    j = run_conseq(tmpdir, """
    rule b:
        outputs: {"finished": "true", "mut":{"$value": "3"}}
        run "bash -c echo test"
    """, targets=["b"])
    objs = j.find_objs({})
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
    assert len(j.find_objs({}))==1

    j = run_conseq(tmpdir, """
    rule b:
        inputs: in={"finished": "true"}
        outputs: {"name": "result", "filename": {"$filename":"stdout.txt"}}
        run "bash" with "echo {{inputs.in.other}}"
    """)
    results = j.find_objs({"name":"result"})
    assert len(results)==1
    stdout = open(results[0]["filename"]["$filename"]).read()
    assert "apple\n" == stdout
