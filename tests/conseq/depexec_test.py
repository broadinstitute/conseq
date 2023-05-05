import os

from conseq import dep
from conseq import depexec
from conseq.depexec import reconcile_db
from conseq.template import create_jinja2_env


class MockRule:
    def __init__(self, executor, resources):
        self.executor = executor
        self.resources = resources


class MockRules:
    def get_rule(self, name):
        return MockRule("p" + name[1], {"slots": 1})


class MockJob:
    def __init__(self, id, transform):
        self.id = id
        self.transform = transform


def test_serial_execution():
    rules = MockRules()

    resources_per_client = {"p1": {"slots": 1}}

    pending_jobs = [MockJob("1", "t1"), MockJob("2", "t1")]
    executing = []
    jobs = depexec.get_satisfiable_jobs(rules, resources_per_client, pending_jobs, [])
    assert len(jobs) == 1

    pending_jobs = [MockJob("2", "t1")]
    executing = [MockJob("1", "t1")]
    jobs = depexec.get_satisfiable_jobs(
        rules, resources_per_client, pending_jobs, executing
    )
    assert len(jobs) == 0


def test_parallel_execution():
    rules = MockRules()

    resources_per_client = {"p1": {"slots": 1}, "p2": {"slots": 1}}

    pending_jobs = [MockJob("1", "t1"), MockJob("2", "t2"), MockJob("3", "t1")]
    executing = []
    jobs = depexec.get_satisfiable_jobs(
        rules, resources_per_client, pending_jobs, executing
    )
    assert len(jobs) == 2

    pending_jobs = [MockJob("3", "t1")]
    executing = [MockJob("1", "t1"), MockJob("2", "t2")]
    jobs = depexec.get_satisfiable_jobs(
        rules, resources_per_client, pending_jobs, executing
    )
    assert len(jobs) == 0


from hashlib import md5


def _run_with_config(tmpdir, counters, config_str):
    state_dir = str(tmpdir.join("state"))
    depfile = str(
        tmpdir.join(str(md5(config_str.encode("utf-8")).hexdigest()) + ".conseq")
    )
    print("writing", depfile)
    with open(depfile, "wt") as fd:
        fd.write(config_str)

    depexec.main(
        depfile,
        state_dir,
        forced_targets=[],
        override_vars={},
        max_concurrent_executions=1,
        capture_output=False,
        req_confirm=False,
        config_file=None,
        remove_unknown_artifacts=True,
    )

    db_path = os.path.join(state_dir, "db.sqlite3")
    j = dep.open_job_db(db_path)
    # copy counters onto j for testing
    for k, v in counters.items():
        setattr(j, k, v)
    return j


# def signal_remove_obj(id):
#     pass
#
#
# def signal_remove_rule(id):
#     pass
#
#
# def signal_remove_rule_execution(id):
#     pass
#
#
# def signal_add_obj(id, space, props):
#     pass


def test_rule_reconcile(tmpdir, monkeypatch):
    counters = {}

    def increment_counter_callback(field):
        def fn(*args, **kwargs):
            counters[field] += 1

        return fn

    # record the number of times these functions have been called
    monkeypatch.setattr(
        dep, "signal_add_obj", increment_counter_callback("new_artifacts")
    )
    monkeypatch.setattr(
        dep, "signal_remove_obj", increment_counter_callback("del_artifacts")
    )

    def run_with_config(config_str):
        counters.update({"new_artifacts": 0, "del_artifacts": 0})
        return _run_with_config(tmpdir, counters, config_str)

    db_path = os.path.join(str(tmpdir), "db.sqlite3")

    # depexec.main(filename, state_dir, targets, {}, 10, False, False, None)
    j = dep.open_job_db(db_path)

    # create a few artifacts
    j = run_with_config(
        """
        rule a:
            outputs: {"type": "a-out"}    
        rule b:
            outputs: {"type": "b-out"}    
        rule c1:
            outputs: {"type": "c1-out"}    
    """
    )

    assert j.new_artifacts == 3
    assert j.del_artifacts == 0

    # now run again, but with an additional rule. Shouldn't delete anything, just add one more artifact
    j = run_with_config(
        """
        rule a:
            outputs: {"type": "a-out"}    
        rule b:
            outputs: {"type": "b-out"}    
        rule c1:
            outputs: {"type": "c1-out"}    
        rule c2:
            inputs: in={"type": "c1-out"}
            outputs: {"type": "c2-out"}    
    """
    )

    assert j.new_artifacts == 1
    assert j.del_artifacts == 0

    # but if we change a rule, we should delete that artifact and create a new one
    j = run_with_config(
        """
        rule a:
            outputs: {"type": "a-out"}    
        rule b:
            outputs: {"type": "b-out-2"}   
        rule c1:
            outputs: {"type": "c1-out"}    
        rule c2:
            inputs: in={"type": "c1-out"}
            outputs: {"type": "c2-out"}    
    """
    )
    assert j.new_artifacts == 1
    assert j.del_artifacts == 1

    # Lastly, changing a rule should delete downstream artifacts too
    j = run_with_config(
        """
        rule a:
            outputs: {"type": "a-out"}    
        rule b:
            outputs: {"type": "b-out-2"}   
        rule c1:
            outputs: {"type": "c1-out-2"}    
        rule c2:
            inputs: in={"type": "c1-out"}
            outputs: {"type": "c2-out"}    
    """
    )
    assert j.new_artifacts == 1
    assert j.del_artifacts == 2


def test_obj_reconcile(tmpdir):
    db_path = os.path.join(str(tmpdir), "db.sqlite3")

    # depexec.main(filename, state_dir, targets, {}, 10, False, False, None)
    j = dep.open_job_db(db_path)

    # verify empty
    objs = j.find_objs(dep.PUBLIC_SPACE, {})
    assert len(objs) == 0

    jinja2_env = create_jinja2_env()

    vars = {}
    objs = [{"type": "a"}, {"type": "b"}]
    reconcile_db(j, jinja2_env, {}, objs, vars, force=True)

    # verify two objects were created
    objs = j.find_objs(dep.PUBLIC_SPACE, {})
    assert len(objs) == 2

    objs = [{"type": "a"}, {"type": "b"}, {"type": "c"}]
    reconcile_db(j, jinja2_env, {}, objs, vars, force=True)

    # type=c is the new object, getting us to 3
    objs = j.find_objs(dep.PUBLIC_SPACE, {})
    assert len(objs) == 3

    # now if we drop type=a, we should be back down to two objects
    objs = [{"type": "b"}, {"type": "c"}]
    reconcile_db(j, jinja2_env, {}, objs, vars, force=True)

    # type=c is the new object, getting us to 3
    objs = j.find_objs(dep.PUBLIC_SPACE, {})
    assert len(objs) == 2
