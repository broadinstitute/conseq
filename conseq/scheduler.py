from collections import defaultdict
from typing import Sequence

START = "__start__"


class Deps:
    def __init__(self, name: str, after_each: Sequence[str], after_all: Sequence[str]):
        self.name = name
        self.after_each = after_each
        self.after_all = after_all


class ConstrainedDeps:
    def __init__(self, name: str, after_each: Sequence[str], exclusive: Sequence[str]):
        self.name = name
        self.after_each = after_each
        self.exclusive = set(exclusive)  # a list of rules that this rule must wait for to complete if any are active

    def __repr__(self):
        return "ConstrainedDeps(name={}, after_each={}, exclusive={})".format(self.name, self.after_each, self.exclusive)


class Scheduler:
    def __init__(self, deps: Sequence[Deps]):
        self.rules_in_use_count = defaultdict(lambda: 0)
        self.rules_in_use_count[START] += 1

        # rules which we cannot execute now because they need to wait for some other rule to be fully finished.
        self.waiting_for_exclusion = []

        # a map of rule name -> the ConstrainedDeps which had rule name in its after_each
        self.waiting_for_completion = defaultdict(lambda: [])

        # first pass, record the dependency tree of for_each in by_child
        by_child = defaultdict(lambda: [])  # child name -> parent name
        by_name = {}

        for dep in deps:
            assert dep.name not in by_name, "Had more then one dependency definition for {}".format(dep.name)
            by_name[dep.name] = dep

            for parent_name in dep.after_each:
                by_child[dep.name].append(parent_name)

        def get_all_ancestors(name):
            parent_names = by_child[name]
            if parent_names == [START]:
                return set()
            else:
                return set(parent_names).union(*[get_all_ancestors(parent_name) for parent_name in parent_names])

        # second pass, create ConstrainedDeps by computing 'exclusive' based on ancestry
        for dep in deps:
            # compute exclusive as all rules which could result in an execution of the rule we need to wait for.
            exclusive = set(dep.after_all)
            for after_all_rule in dep.after_all:
                exclusive.update(get_all_ancestors(after_all_rule))

            cdep = ConstrainedDeps(dep.name, dep.after_each, exclusive)

            for predecesor_rule in cdep.after_each + dep.after_all:
                self.waiting_for_completion[predecesor_rule].append(cdep)

    @property
    def rules_in_use(self):
        return set([name for name, count in self.rules_in_use_count.items() if count > 0])

    def _update_waiting_and_get_ready_try(self, rules_in_use, cds_to_consider):
        next_waiting_for_exclusion = []
        ready_rules = []
        for constrained_deps in cds_to_consider:

            # if there is a rule in use that prevents us from running this now, put this in waiting
            blocking_rules = rules_in_use.intersection(constrained_deps.exclusive)
            print("blocking_rules", blocking_rules)
            if len(blocking_rules) > 0:
                next_waiting_for_exclusion.append(constrained_deps)
            else:
                print("ready_rules append", constrained_deps.name)
                ready_rules.append(constrained_deps.name)

        waiting_for_exclusion = next_waiting_for_exclusion
        print("_update_waiting_and_get_ready waiting_for_exclusion={}", self.waiting_for_exclusion)
        print("ready_rules", ready_rules)
        return ready_rules, waiting_for_exclusion

    def _update_waiting_and_get_ready(self, cds_to_consider):
        rules_in_use = set(self.rules_in_use)
        prev_ready_rules = None

        # find which rules are ready to run, except make sure any that we add don't result in exclusions by running the process
        # again until we reach a fixed point.
        while True:
            ready_rules, waiting_for_exclusion = self._update_waiting_and_get_ready_try(rules_in_use, cds_to_consider)
            # if we haven't pruned out any additional rules, break out of loop
            if ready_rules == prev_ready_rules:
                break
            # otherwise, update our list of rules that would be in use and try again
            rules_in_use.update(ready_rules)
            prev_ready_rules = ready_rules

        self.waiting_for_exclusion = waiting_for_exclusion

        return ready_rules

    def start(self, names: Sequence[str]):
        for name in names:
            self.rules_in_use_count[name] += 1

        return self._update_waiting_and_get_ready(self.waiting_for_exclusion)

    def completed(self, name):

        # update the rules in use after determining ready in case we are waiting on a chain of dependencies
        self.rules_in_use_count[name] -= 1
        assert self.rules_in_use_count[name] >= 0

        ready = self._update_waiting_and_get_ready(self.waiting_for_exclusion + self.waiting_for_completion[name])

        return ready


def test_linear():
    s = Scheduler([
        Deps("A", after_each=[START], after_all=[]),
        Deps("B", after_each=["A"], after_all=[]),
        Deps("C", after_each=["B"], after_all=[]),
    ])

    next_rules = s.completed(START)
    assert set(next_rules) == set("A")

    assert len(s.start(["A"])) == 0
    next_rules = s.completed("A")
    assert set(next_rules) == set("B")

    assert len(s.start(["B"])) == 0
    next_rules = s.completed("B")
    assert set(next_rules) == set("C")

    assert len(s.start(["C"])) == 0
    next_rules = s.completed("C")
    assert len(next_rules) == 0


def test_fork_join():
    s = Scheduler([
        Deps("A", after_each=[START], after_all=[]),
        Deps("B", after_each=[START], after_all=[]),
        Deps("C", after_each=["A", "B"], after_all=[]),
        Deps("D", after_each=["C"], after_all=[]),
    ])

    next_rules = s.completed(START)
    assert set(next_rules) == set(["A", "B"])

    assert len(s.start(["B", "A"])) == 0
    next_rules = s.completed("B")
    assert set(next_rules) == set("C")

    next_rules = s.completed("A")
    assert set(next_rules) == set("C")

    assert len(s.start("C")) == 0
    next_rules = s.completed("C")
    assert set(next_rules) == set("D")

    assert len(s.start("D")) == 0
    next_rules = s.completed("D")
    assert len(next_rules) == 0


def test_linear_with_for_all():
    s = Scheduler([
        Deps("A", after_each=[START], after_all=[]),
        Deps("B", after_each=[], after_all=["A"]),
        Deps("C", after_each=["B"], after_all=[]),
    ])

    next_rules = s.completed(START)
    assert set(next_rules) == set("A")

    assert len(s.start(["A", "A"])) == 0
    next_rules = s.completed("A")
    assert set(next_rules) == set()
    next_rules = s.completed("A")
    assert set(next_rules) == set("B")

    assert len(s.start(["B"])) == 0
    next_rules = s.completed("B")
    assert set(next_rules) == set("C")

    assert len(s.start(["C"])) == 0
    next_rules = s.completed("C")
    assert len(next_rules) == 0


def test_fork_join_with_for_All():
    s = Scheduler([
        Deps("A", after_each=[START], after_all=[]),
        Deps("B", after_each=[START], after_all=[]),
        Deps("C", after_each=["A", "B"], after_all=[]),
        Deps("D", after_each=[], after_all=["C"]),
    ])

    next_rules = s.completed(START)
    assert set(next_rules) == set(["A", "B"])

    assert len(s.start(["A", "A", "B"])) == 0
    next_rules = s.completed("B")
    assert set(next_rules) == set("C")
    next_rules = s.completed("A")
    assert set(next_rules) == set("C")
    assert len(s.start(["C"])) == 0
    next_rules = s.completed("C")
    assert set(next_rules) == set()

    next_rules = s.completed("A")
    assert set(next_rules) == set("C")
    assert len(s.start(["C"])) == 0
    next_rules = s.completed("C")

    assert set(next_rules) == set("D")

    assert len(s.start(["D"])) == 0
    next_rules = s.completed("D")
    assert len(next_rules) == 0


from typing import Set
from typing import Dict, Tuple, Union

FOR_EACH = "for_each"
FOR_ALL = "for_all"


class Input:
    def __init__(self, name: str, type: str, fixed_attributes: Dict[str, str], other_attributes: Sequence[str]):
        self.type = type
        self.name = name
        self.fixed_attributes = fixed_attributes
        self.other_attributes = other_attributes


class Output:
    def __init__(self, fixed_attributes: Dict[str, str], other_attributes: Sequence[str]):
        self.fixed_attributes = fixed_attributes
        self.other_attributes = other_attributes


class Rule:
    def __init__(self, name: str, inputs: Sequence[Input], outputs: Sequence[Output]):
        self.name = name
        self.inputs = list(inputs)
        self.outputs = list(outputs)


def compute_deps_from_rules(rules: Sequence[Rule]) -> Sequence[Deps]:
    result = []

    by_output = PartialKeyIndex()
    for rule in rules:
        for output in rule.outputs:
            by_output.add(output.fixed_attributes, output.other_attributes, rule.name)

    for rule in rules:
        if len(rule.inputs) == 0:
            result.append(Deps(rule.name, [START], []))
        else:
            foreach = []
            forall = []
            for input in rule.inputs:
                pred_rule_names = by_output.get(input.fixed_attributes, input.other_attributes)
                assert len(pred_rule_names) > 0
                if rule.type == FOR_EACH:
                    foreach.extend(pred_rule_names)
                else:
                    assert rule.type == FOR_ALL
                    forall.extend(pred_rule_names)

            result.append(Deps(rule.name, foreach, forall))

    return result


def _is_compatible_with(fixed_attributes: Sequence[Tuple[str, str]], attribute_names: Set[str],
                        _fixed_attributes: Sequence[Tuple[str, str]], _attribute_names: Set[str]):
    if not attribute_names.issubset(_attribute_names):
        return False

    f_d = dict(_fixed_attributes)
    for key, value in fixed_attributes:
        if key in f_d:
            if f_d[key] != value:
                return False

    return True


class Wildcard:
    pass


ANY_VALUE = Wildcard()


def _split_attributes(attributes):
    fixed_attributes = set()
    all_attributes = set()
    for name, value in attributes:
        if value != ANY_VALUE:
            fixed_attributes.add((name, value))
        all_attributes.add(name)
    return fixed_attributes, all_attributes


class PartialKeyIndex:
    def __init__(self):
        self.d = defaultdict(lambda: [])

    def add(self, attributes: Sequence[Tuple[str, Union[str, Wildcard]]], value):
        fixed_attributes, all_attributes = _split_attributes(attributes)

        entry = (fixed_attributes, all_attributes, value)
        for component in fixed_attributes:
            self.d[component].append(entry)

    def get(self, attributes: Sequence[Tuple[str, Union[str, Wildcard]]]):
        fixed_attributes, all_attributes = _split_attributes(attributes)

        single_component_matches = []
        for component in fixed_attributes:
            matches = self.d[component]
            if len(matches) == 0:
                return []
            single_component_matches.append(matches)

        # use the component that is most selective to minimize the number of other keys we need to check
        single_component_matches.sort(key=lambda x: len(x))
        smallest = single_component_matches[0]

        result = []
        for _fixed_attributes, _other_attributes, value in smallest:
            if _is_compatible_with(fixed_attributes, all_attributes, _fixed_attributes, _other_attributes):
                result.append(value)

        return result


def test_satisfies():
    assert _is_compatible_with([("A", "a")], set(["A", "B"]),
                               [("A", "a")], set(["A", "B"]))

    assert _is_compatible_with([("A", "a")], set(["A"]),
                               [("A", "a")], set(["A", "B"]))

    assert not _is_compatible_with([("A", "a")], set(["A"]),
                                   [("A", "b")], set(["A", "B"]))

    assert not _is_compatible_with([("A", "a")], set(["A", "C"]),
                                   [("A", "a")], set(["A", "B"]))


def test_partial_key_index():
    p = PartialKeyIndex()
    p.add([("A", "a"), ("B", "b"), ("C", "c")], "1")
    p.add([("A", "a"), ("B", "b2")], "2")
    p.add([("A", "a"), ("D", "d")], "3")

    assert p.get([("D", "d")]) == ["3"]
    assert set(p.get([("A", "a")])) == set(["1", "2", "3"])
    assert p.get([("A", "a"), ("B", "b2")]) == ["2"]

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
