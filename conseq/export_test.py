from conseq import export_cmd
from conseq import depexec, dep
import os


def test_export_import(tmpdir):
    state1_dir=str(tmpdir)+"/state1"
    state2_dir=str(tmpdir)+"/state2"
    config1 = str(tmpdir)+"/1.conseq"
    config2 = str(tmpdir)+"/2.conseq"
    with open(config1, "wt") as fd:
        fd.write("""
    rule a:
        outputs: {"type": "thing", "$hash": "1"}
    rule b:
        inputs: in={"type": "thing"}
        outputs: {"type": "otherthing"}
    """)

    # run config1
    depexec.main(config1, state1_dir, [], {}, 10, False, False, None)

    # confirm everything worked okay
    j = dep.open_job_db(os.path.join(state1_dir, "db.sqlite3"))
    assert len(j.get_all_executions()) == 2

    # export to make config2
    export_cmd.export_conseq(state1_dir, config2, None)

    # now try running config2
    depexec.main(config2, state2_dir, [], {}, 10, False, False, None)

    # verify the executions are there, as well as the objects
    j = dep.open_job_db(os.path.join(state2_dir, "db.sqlite3"))
    assert len(j.get_all_executions()) == 2
    assert len(j.find_objs(j.get_current_space(), {})) == 2

    # and if we re-run config1 with state2 then nothing should happen because everything is already done.
    export_cmd.export_conseq(state2_dir, config1, None)
    assert len(j.get_all_executions()) == 2
