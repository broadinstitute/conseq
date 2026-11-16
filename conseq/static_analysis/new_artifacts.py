from typing import Dict, Iterable, List, Set

from .convert import _convert_literal_output, convert_rules
from .dag import IdentityDict, artifact_satisfies_constraints, createDAG


def rules_invalidated_by_new_inputs(
    rules, new_artifacts: Iterable[dict], new_rules: Iterable[str] = ()
) -> Dict[str, List[str]]:
    """Finds the rules with an "all" input whose previous results can't be trusted, because new
    artifacts will be available to them (directly, or through the rules which feed them).

    A rule with an "all" input runs once on the whole list of matching artifacts. If any new
    artifact is an input to that rule or to any rule upstream of it, the list might now be different
    (or longer), and the outputs from the earlier execution are out of date. The same is true if
    a rule which is new (it wasn't in the file the last time conseq ran) is upstream of the rule,
    since it could produce artifacts which the rule consumes.

    This is deliberately conservative. It only asks whether a new artifact *could* match
    an input, or a new rule *could* feed one. It doesn't try to work out whether the list really changes.

    :param rules: the rules read from the conseq file
    :param new_artifacts: the properties of the artifacts which are about to be added
    :param new_rules: the names of rules which weren't in the file the previous time
    :returns: for each affected rule, a description of the new artifacts or rules which caused it
       to be affected
    """
    new_artifacts = list(new_artifacts)
    new_rule_names = set(new_rules)
    if len(new_artifacts) == 0 and len(new_rule_names) == 0:
        return {}

    dag = createDAG(convert_rules(rules))
    artifacts = [_convert_literal_output(a).artifact for a in new_artifacts]

    # which new artifacts could be consumed by each rule
    fed_by: Dict[str, List[int]] = {}
    for node in dag.rules:
        for binding in node.rule.inputs:
            for index, artifact in enumerate(artifacts):
                if artifact_satisfies_constraints(
                    artifact, binding.constraints, IdentityDict()
                ):
                    fed_by.setdefault(node.rule.name, [])
                    if index not in fed_by[node.rule.name]:
                        fed_by[node.rule.name].append(index)

    upstream: Dict[str, Set[str]] = {
        node.rule.name: {m.produced_by.rule.name for m in node.inputs}
        for node in dag.rules
    }

    # for each rule, why its inputs might have changed: the new artifacts which feed it or anything
    # upstream of it, and any new rules upstream of it
    reasons_cache: Dict[str, Dict[str, str]] = {}

    def reasons_for(name: str) -> Dict[str, str]:
        if name in reasons_cache:
            return reasons_cache[name]
        # (the graph has no cycles. createDAG would have refused it)
        result: Dict[str, str] = {}
        for index in fed_by.get(name, []):
            result[
                f"artifact {index}"
            ] = f"new artifact {new_artifacts[index]} feeds rule {name}"
        for up in sorted(upstream[name]):
            if up in new_rule_names:
                result[f"rule {up}"] = f"rule {up} is new and could produce its inputs"
            for key, reason in reasons_for(up).items():
                result.setdefault(key, reason)
        reasons_cache[name] = result
        return result

    affected: Dict[str, List[str]] = {}
    for node in dag.rules:
        if not any(b.cardinality == "all" for b in node.rule.inputs):
            continue
        reasons = reasons_for(node.rule.name)
        if len(reasons) > 0:
            affected[node.rule.name] = list(reasons.values())
    return affected
