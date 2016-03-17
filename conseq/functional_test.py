#from . import parser
from . import depexec
from . import dep
import os

def run_conseq(tmpdir, config, targets=[], assert_clean=True):
    state_dir=str(tmpdir)+"/state"
    filename = str(tmpdir)+"/t.conseq"
    with open(filename, "wt") as fd:
        fd.write(config)

    db_path = os.path.join(state_dir, "db.sqlite3")
    if assert_clean:
        assert not os.path.exists(db_path)

    depexec.main(filename, state_dir, targets, {}, 10, False, False)
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
    """)
    assert len(j.get_all_executions()) == 2
