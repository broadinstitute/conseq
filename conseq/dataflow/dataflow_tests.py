from .models import ANY_VALUE
from .dataflow import DataFlow, RuleModel, construct_dataflow

def test_execution_graph():
    g = DataFlow()
    g.add_rule(RuleModel("Mill", {"in": [("type", "tree"), ("height", ANY_VALUE)]}, [[("type", "lumber")]]))
    g.add_rule(RuleModel("Factory", {"in": [("type", "lumber")]}, [[("type", "chairs")]]))
    g.add_artifact([("type", "tree"), ("height", "10ft")])
    g.done()

    assert len(g.get_artifacts()) == 3
    assert len(g.get_rules()) == 2


def test_upstream(tmpdir):
    from conseq.config import read_rules
    state_dir = tmpdir.join("state")
    state_dir.mkdir()

    depfile = tmpdir.join("dep.conseq")
    depfile.write("""
rule a:
    outputs: {"type": "a"}

rule b:
    inputs: in = {"type": "a"}
    outputs: {"type": "b"}

rule c:
    inputs: in = {"type": "b"}
    outputs: {"type": "c"}

rule d:
    inputs: in = {"type": "c"}
    outputs: {"type": "d"}

rule e:
    inputs: in = {"type": "d"}
    outputs: {"type": "e"}

    """)

    configfile = tmpdir.join("config.conseq")
    configfile.write("")

    rules = read_rules(str(state_dir), str(depfile), str(configfile))
    g = construct_dataflow(rules)

    assert sorted(g.get_upstream_rules("c")) == ["a", "b"]
    assert sorted(g.get_downstream_rules("c") ) == ["d", "e"]

    # for visualization of execution profile we want a list of Rule1 -> output, output -> Rule2 and a definition for output

    # import time
    #
    #
    # def trigger_downstream_rules(rule_name):
    #     # generate applications of rules based on previous completion
    #     while True:
    #         for rule_name in rules_to_check:
    #             applications = rules.get_applications(rule_name)
    #             applications = filter_applications_by_existing(applications, skipped, db)
    #
    #         # after we've determined all our applications that we can make, notify the scheduler these rules are in use
    #         new_application_rules = set([a.rule_name for a in applications])
    #         rules_to_check = scheduler.start(new_application_rules)
    #
    #         if len(rules_to_check) == 0:
    #             break
    #
    #
    # def main_loop(scheduler: Scheduler, rules):
    #     trigger_downstream_rules(START)
    #
    #     while True:
    #         completed_executions = get_completed()
    #         if len(completed_executions) == 0:
    #             time.sleep(5)
    #             continue
    #
    #         for completed_execution in completed_executions:
    #             trigger_downstream_rules(completed_execution.rule_name)

