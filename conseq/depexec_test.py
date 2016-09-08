from conseq import depexec
class MockRule:
    def __init__(self, executor, resources):
        self.executor = executor
        self.resources = resources

class MockRules:
    def get_rule(self, name):
        return MockRule("p"+name[1], {"slots":1})

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

