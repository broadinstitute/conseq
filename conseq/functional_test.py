from . import parser
from . import depexec
from . import dep
import os

def run_conseq(tmpdir, config, targets=[]):
    state_dir=str(tmpdir)+"/state"
    filename = str(tmpdir)+"/t.conseq"
    with open(filename, "wt") as fd:
        fd.write(config)
    depexec.main(filename, state_dir, targets, {})
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

def test_nonzero_retcode(tmpdir):
    j = run_conseq(tmpdir, """
    rule a:
        run "bash non-existant-file"
    """)
