"""Converts the rules read from a conseq file into the model used for building the dependency graph.

The graph is conservative: when we can't tell statically what an input will match or what an output
will contain, we assume it could match (or be) anything, so we never miss a dependency.
"""
from typing import Any, List

from conseq.parser import RegEx
from conseq.parser import Rule as ConseqRule

from .model import (
    UNKNOWN,
    Artifact,
    Binding,
    Constraints,
    OutputArtifact,
    Pair,
    Rule,
)


def _is_template(value: Any) -> bool:
    return isinstance(value, str) and ("{{" in value or "{%" in value)


def _convert_input(input_spec) -> Binding:
    constraints = []
    for key, value in input_spec.json_obj.items():
        # We can only use constraints which are fixed strings or regular expressions. Anything
        # else (a query variable shared with another input, a template which depends on the
        # config, a file reference) is left out, which means the input matches more artifacts.
        if isinstance(value, RegEx):
            constraints.append(Pair(key, value))
        elif isinstance(value, str) and not _is_template(value):
            constraints.append(Pair(key, value))

    return Binding(
        variable=input_spec.variable,
        cardinality="all" if input_spec.for_all else "one",
        constraints=Constraints(constraints),
    )


def _convert_literal_output(output: dict) -> OutputArtifact:
    properties = []
    is_open = False
    for key, value in output.items():
        if _is_template(key):
            # we can't know the name of this property
            is_open = True
            continue

        if isinstance(value, str) and not _is_template(value):
            properties.append(Pair(key, value))
        else:
            # a template, or a reference to a file or similar. Some value, but we can't say which
            properties.append(Pair(key, UNKNOWN))
    return OutputArtifact(Artifact(properties, open=is_open), "one")


def _convert_output_type(output_type) -> OutputArtifact:
    type_def = output_type.type_def
    properties = [Pair("type", type_def.name)]
    properties.extend(Pair(field, UNKNOWN) for field in type_def.fields)
    # artifacts are allowed to have more properties than the required fields of their type
    cardinality = "one" if output_type.cardinality.max == 1 else "many"
    return OutputArtifact(Artifact(properties, open=True), cardinality)


def convert_rule(rule: ConseqRule) -> Rule:
    outputs: List[OutputArtifact] = []
    if rule.outputs is not None:
        outputs.extend(_convert_literal_output(o) for o in rule.outputs)
    if rule.resolved_output_types is not None:
        outputs.extend(_convert_output_type(t) for t in rule.resolved_output_types)

    if (
        rule.outputs is None
        and rule.resolved_output_types is None
        and not rule.is_publish_rule
    ):
        # config.py refuses to load rules like this, so it indicates a bug if we get here
        raise Exception(f"rule {rule.name} doesn't say what it produces")

    return Rule(
        name=rule.name,
        inputs=[_convert_input(i) for i in rule.inputs],
        outputs=outputs,
        is_publish_rule=rule.is_publish_rule,
    )


def convert_rules(rules) -> List[Rule]:
    return [convert_rule(rule) for rule in rules]
