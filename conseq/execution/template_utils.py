from conseq.template import expand_dict_item, expand_dict
from conseq.template import render_template
from ..types import PropsType
import six
import re
from jinja2.environment import Environment
from conseq.dep import Template
from typing import Tuple, Dict, List, Any
import collections
from conseq import dep, depexec
from conseq.parser import Rule
from conseq.parser import QueryVariable, RegEx
from conseq.query import  ForEach

def to_template(jinja2_env: Environment, rule: Rule, config: PropsType) -> Template:
    queries, predicates = convert_input_spec_to_queries(jinja2_env, rule, config)
    return dep.Template(
        queries,
        predicates,
        rule.name,
        output_matches_expectation=make_output_check(rule),
    )

def expand_run(
    jinja2_env: Environment,
    command: str,
    script_body: None,
    config: PropsType,
    **kwargs,
) -> Tuple[str, None]:
    command = render_template(jinja2_env, command, config, **kwargs)
    if script_body != None:
        script_body = render_template(jinja2_env, script_body, config, **kwargs)
    return (command, script_body)

def expand_outputs(
    jinja2_env: Environment, output: PropsType, config: PropsType, **kwargs,
) -> PropsType:
    return expand_dict(jinja2_env, output, config, **kwargs)


def expand_input_spec(
    jinja2_env: Environment, spec: Dict[str, str], config: PropsType,
) -> Dict[str, str]:

    expanded = {}

    for k, v in spec.items():
        # if the value is a regexp, don't expand
        if isinstance(v, six.string_types):
            k, v = expand_dict_item(jinja2_env, k, v, config)
        elif isinstance(v, QueryVariable):
            k = render_template(jinja2_env, k, config)
        else:
            assert isinstance(v, RegEx)
            k = render_template(jinja2_env, k, config)
            v = re.compile(render_template(jinja2_env, v.expression, config))

        expanded[k] = v

    return expanded


def convert_input_spec_to_queries(
    jinja2_env: Environment, rule: Rule, config: PropsType
) -> Tuple[List[ForEach], List[Any]]:
    queries = []
    predicates = []
    pairs_by_var = collections.defaultdict(lambda: [])
    for input in rule.inputs:
        bound_name, spec, for_all = input.variable, input.json_obj, input.for_all
        assert bound_name != ""
        spec = expand_input_spec(jinja2_env, spec, config)

        constants = {}
        for prop_name, value in spec.items():
            if isinstance(value, QueryVariable):
                pairs_by_var[value.name].append((bound_name, prop_name))
            else:
                constants[prop_name] = value
        if for_all:
            q = dep.ForAll(bound_name, constants)
        else:
            q = dep.ForEach(bound_name, constants)

        queries.append(q)

    for var, pairs in pairs_by_var.items():
        predicates.append(dep.PropsMatch(pairs))

    return queries, predicates

def make_output_check(rule: Rule):
    def is_outputs_good(outputs: List[Dict]):
        if rule.resolved_output_types is None:
            return True

        # index by type name
        type_by_name = {x.type_def.name: x for x in rule.resolved_output_types}

        # count number of outputs per type for verifing cardinality checks
        per_type_count = defaultdict(lambda: 0)
        for output in outputs:
            per_type_count[output["type"]] += 1

        okay = True

        # check cardinalities
        for output_type in rule.resolved_output_types:
            output_count = per_type_count[output_type.type_def.name]
            if output_count > output_type.cardinality.min:
                print(
                    "Warning: rule {rule.name} created {output_count} outputs with type {output_type.type_def.name} but expected at least {output_type.cardinality.min}",
                    flush=True,
                )
                okay = False
            if (
                output_type.cardinality.max is not None
                and output_count < output_type.cardinality.max
            ):
                print(
                    "Warning: rule {rule.name} created {output_count} outputs with type {output_type.type_def.name} but expected at most {output_type.cardinality.max}",
                    flush=True,
                )
                okay = False

        for output in outputs:
            output_type = output["type"]
            type_def = type_by_name.get(output_type)
            if type_def is None:
                print(
                    f"Warning: rule {rule.name} created output with type {output_type} but that was not included in the output_types section of the rule"
                )
                continue

            expected_fields = set(type_def.type_def.fields)
            present_fields = set(output.keys())
            missing_fields = expected_fields.difference(present_fields)
            extra_fields = present_fields.difference(expected_fields)
            if len(missing_fields) > 0:
                print(
                    f"Warning: output with type {output_type} from {rule.name} was missing properties: {', '.join(missing_fields)}",
                    flush=True,
                )
                okay = False
            if len(extra_fields) > 0:
                print(
                    f"Warning: output with type {output_type} from {rule.name} had extra properties: {', '.join(extra_fields)}",
                    flush=True,
                )
                okay = False

        return okay

    return is_outputs_good
