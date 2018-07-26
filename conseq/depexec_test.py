from conseq import depexec


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
    jobs = depexec.get_satisfiable_jobs(rules, resources_per_client, pending_jobs, executing)
    assert len(jobs) == 0


def test_parallel_execution():
    rules = MockRules()

    resources_per_client = {"p1": {"slots": 1}, "p2": {"slots": 1}}

    pending_jobs = [MockJob("1", "t1"), MockJob("2", "t2"), MockJob("3", "t1")]
    executing = []
    jobs = depexec.get_satisfiable_jobs(rules, resources_per_client, pending_jobs, executing)
    assert len(jobs) == 2

    pending_jobs = [MockJob("3", "t1")]
    executing = [MockJob("1", "t1"), MockJob("2", "t2")]
    jobs = depexec.get_satisfiable_jobs(rules, resources_per_client, pending_jobs, executing)
    assert len(jobs) == 0


def test_obj_reconcile(tmpdir):
    import os
    from conseq import dep
    from conseq.depexec import process_add_if_missing
    from conseq.template import create_jinja2_env

    db_path = os.path.join(str(tmpdir), "db.sqlite3")

    # depexec.main(filename, state_dir, targets, {}, 10, False, False, None)
    j = dep.open_job_db(db_path)

    # verify empty
    objs = j.find_objs(dep.DEFAULT_SPACE, {})
    assert len(objs) == 0

    jinja2_env = create_jinja2_env()

    vars = {}
    objs = [{"type": "a"}, {"type": "b"}]
    process_add_if_missing(j, jinja2_env, objs, vars, force=True)

    # verify two objects were created
    objs = j.find_objs(dep.DEFAULT_SPACE, {})
    assert len(objs) == 2

    objs = [{"type": "a"}, {"type": "b"}, {"type": "c"}]
    process_add_if_missing(j, jinja2_env, objs, vars, force=True)

    # type=c is the new object, getting us to 3
    objs = j.find_objs(dep.DEFAULT_SPACE, {})
    assert len(objs) == 3

    # now if we drop type=a, we should be back down to two objects
    objs = [{"type": "b"}, {"type": "c"}]
    process_add_if_missing(j, jinja2_env, objs, vars, force=True)

    # type=c is the new object, getting us to 3
    objs = j.find_objs(dep.DEFAULT_SPACE, {})
    assert len(objs) == 2
