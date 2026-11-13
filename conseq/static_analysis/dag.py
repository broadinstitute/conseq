import re
from typing import Union

from conseq.exceptions import CycleDetected, UnreachableRules
from conseq.parser import RegEx

from .model import (
    DAG,
    UNKNOWN,
    Artifact,
    ArtifactMatchNode,
    Blockers,
    Constraints,
    Rule,
    RuleNode,
    Unknown,
)


def artifact_satisfies_constraints(
    artifact: Artifact, constraints: Constraints, cache: "IdentityDict",
) -> bool:
    """
    Check if an artifact satisfies the given constraints.

    Args:
        artifact: Artifact with the artifact properties
        constraints: Constraints object with properties to match against

    Returns:
        bool: True if the artifact satisfies all constraints, False otherwise. An artifact which
        doesn't have a property that is constrained doesn't satisfy the constraints.
    """
    by_name = {p.name: p.value for p in artifact.properties}

    for pair in constraints.properties:
        if pair.name not in by_name:
            # the artifact doesn't have a property which the constraint requires. (If a value
            # might be present but isn't known statically, it's listed with the value UNKNOWN.)
            return False

        if isinstance(pair.value, RegEx):
            artifact_value = by_name[pair.name]
            if artifact_value is UNKNOWN:
                # possible so continue
                continue
            else:
                assert isinstance(artifact_value, str)
                if not re.match(pair.value.expression, artifact_value):
                    return False
        else:
            assert isinstance(pair.value, str)
            artifact_value = by_name[pair.name]
            if artifact_value is UNKNOWN:
                # possible so continue
                continue
            else:
                assert isinstance(artifact_value, str)
                if artifact_value != pair.value:
                    return False

    return True


class IdentitySet:
    def __init__(self):
        self.d = IdentityDict()

    def __contains__(self, value):
        return value in self.d

    def add(self, value):
        self.d[value] = value

    def values(self):
        return self.d.values()


class IdentityDict:
    def __init__(self):
        self.m = {}

    def __contains__(self, value):
        return id(value) in self.m

    def __setitem__(self, key, value):
        self.m[id(key)] = value

    def __getitem__(self, key):
        return self.m[id(key)]

    def values(self):
        return self.m.values()


_VISITING = 1
_DONE = 2


def assert_no_cycles(dag: DAG):
    """Checks that the rules form a graph which can be run, starting from the rules which have no
    inputs.

    Raises CycleDetected if a cycle can be reached from one of the roots, and UnreachableRules if
    there are rules which can't be reached from any root at all. (Rules which aren't reachable
    are either in a cycle, or depend on one, so we don't bother to tell those cases apart.)

    Each rule is only explored once, so this is linear in the size of the graph.
    """
    # rule node -> _VISITING if it's on the path we're currently exploring, or _DONE once all of the
    # rules downstream of it have been explored. A rule which is in the dict doesn't need to be
    # explored again.
    state = IdentityDict()

    for root in dag.roots:
        if root in state:
            continue

        # iterative depth-first search so that long chains of rules don't hit the recursion limit
        path = [root]
        remaining_outputs = [iter(root.outputs)]
        state[root] = _VISITING
        while len(path) > 0:
            try:
                output = next(remaining_outputs[-1])
            except StopIteration:
                state[path.pop()] = _DONE
                remaining_outputs.pop()
                continue

            consumer = output.consumed_by
            if consumer in state:
                if state[consumer] == _VISITING:
                    raise CycleDetected(
                        [x.rule.name for x in path] + [consumer.rule.name]
                    )
                continue

            state[consumer] = _VISITING
            path.append(consumer)
            remaining_outputs.append(iter(consumer.outputs))

    unreachable = [node.rule.name for node in dag.rules if node not in state]
    if len(unreachable) > 0:
        raise UnreachableRules(unreachable)


def createDAG(rules: list[Rule]) -> DAG:
    # Create a mapping of property patterns to rule nodes
    rule_nodes = IdentityDict()
    cache = IdentityDict()

    # First pass: create RuleNodes for all rules
    for rule in rules:
        rule_node = RuleNode(rule=rule, inputs=[], outputs=[])
        rule_nodes[rule] = rule_node

    def all_bindings():
        for rule in rules:
            for input in rule.inputs:
                yield rule, input

    def all_artifact_outputs():
        for rule in rules:
            for output in rule.outputs:
                yield rule, output

    # Second pass: For each constraint, find all matching input artifacts and set up bi-directional references
    for binding_rule, binding in all_bindings():
        for output_rule, artifact_output in all_artifact_outputs():

            # if binding_rule.name == "assemble_feature_matrix" and output_rule.name == "make_pred_biomarker_matrix":
            #     breakpoint()
            # if rule.name in ["assemble_feature_matrix", "make_pred_biomarker_matrix"]:
            #     breakpoint()

            if artifact_satisfies_constraints(
                artifact_output.artifact, binding.constraints, cache
            ):
                # The output artifact matches the input constraints of a different rule. So link them up
                match = ArtifactMatchNode(
                    produced_by=rule_nodes[output_rule],
                    binding=binding,
                    artifact=artifact_output,
                    consumed_by=rule_nodes[binding_rule],
                )

                match.produced_by.outputs.append(match)
                match.consumed_by.inputs.append(match)

    # Return the DAG with all rule nodes
    dag = DAG(rules=list(rule_nodes.values()))
    assert_no_cycles(dag)
    return dag


def compute_blockers(dag: DAG) -> list[Blockers]:
    # if a rule has an "all" input, then it needs to wait for all rules which _could_ produce such an artifact
    # to complete before it can start. This determines the set of rules in `start_blocked_by_uncompleted_rules`

    # Similarly a rule cannot be completed if an input _could_ be produced by a rule which is not complete yet
    # This is what determines the set of rules in `start_blocked_by_uncompleted_rules`

    blockers = []
    for rule_node in dag.rules:

        start_blocked_by_uncompleted_rules = IdentitySet()
        completion_blocked_by_uncompleted_rules = IdentitySet()

        for input in rule_node.inputs:
            completion_blocked_by_uncompleted_rules.add(input.produced_by.rule)

            # if we have a node which consumes "all" artifacts, we need to wait for the rules
            # which could possibly create these artifacts to fully complete before we know
            # we have all such artifacts.
            if input.binding.cardinality == "all":
                start_blocked_by_uncompleted_rules.add(input.produced_by.rule)

        blockers.append(
            Blockers(
                rule=rule_node.rule,
                start_blocked_by_uncompleted_rules=list(
                    start_blocked_by_uncompleted_rules.values()
                ),
                completion_blocked_by_uncompleted_rules=list(
                    completion_blocked_by_uncompleted_rules.values()
                ),
            )
        )

    return blockers
