import os
import textwrap
from typing import Optional

from conseq import parser
from conseq.hashcache import HashCache
from conseq.template import LazyConfig
from conseq.template import create_jinja2_env, render_template
from conseq.template import expand_dict
from conseq.parser import Rule, TypeDefStmt
import logging
from typing import Dict

log = logging.getLogger(__name__)


class Rules:
    def __init__(self):
        self.rule_by_name: Dict[str, Rule] = {}
        self.vars = {}
        self.objs = []
        self.types: Dict[str, TypeDefStmt] = {}
        self.exec_clients = {}
        self.remember_executed = []
        self.jinja2_env = create_jinja2_env()
        self.override_names = set()

    def get_rule_specifications(self):
        result = {}
        for transform, instance in self.rule_by_name.items():
            result[transform] = instance.to_json()
        return result

    def add_remember_executed(self, value):
        self.remember_executed.append(value)

    def add_if_missing(self, obj):
        self.objs.append(obj)

    def set_var(self, name, value, is_override=False):
        if is_override:
            assert name not in self.vars
            self.override_names.add(name)
            self.vars[name] = value
        else:
            if name in self.override_names:
                log.warning(
                    "Skipping assignment of %s to %s, because that variable is overriden (value: %s)",
                    repr(name),
                    repr(value),
                    repr(self.vars[name]),
                )
            else:
                if name in self.vars:
                    log.warning(
                        "Overwrote value of %s with %s (was previously %s)",
                        name,
                        value,
                        self.vars.get(name),
                    )
                self.vars[name] = value

    def get_vars(self):
        return dict(self.vars)

    def __iter__(self):
        return iter(self.rule_by_name.values())

    def get_rule(self, name):
        return self.rule_by_name[name]

    def set_rule(self, name, rule: Rule):
        if name in self.rule_by_name:
            raise Exception("Duplicate rules for {}".format(name))
        self.rule_by_name[name] = rule

    def add_client(self, name, client, replace=False):
        if not replace:
            if name in self.exec_clients:
                raise Exception(f"Duplicate executor profiles named {name}")
        else:
            assert name in self.exec_clients
        self.exec_clients[name] = client

    def has_client_defined(self, name):
        return name in self.exec_clients

    def get_client(self, name):
        return self.exec_clients[name]

    def add_type(self, typedef):
        name = typedef.name
        if name in self.types:
            raise Exception("Duplicate type for {}".format(name))
        self.types[name] = typedef

    def __repr__(self):
        return "<Rules vars:{}, rules:{}>".format(self.vars, list(self))


def load_config(config_file):
    config = {}

    p = parser.parse(config_file)
    for dec in p:
        if isinstance(dec, parser.LetStatement):
            config[dec.name] = dec.value
        else:
            raise Exception(
                "Initial config is only allowed to use 'let' statements but encountered {}".format(
                    dec
                )
            )

    return config


def _get_dlcache_dir(state_dir):
    dlcache = os.path.join(state_dir, "dlcache")
    if not os.path.exists(dlcache):
        os.makedirs(dlcache)
    return dlcache


def _make_uuid():
    import uuid

    return uuid.uuid4().hex


def _load_initial_config(state_dir: str, depfile: str, config_file: Optional[str]):
    dlcache = _get_dlcache_dir(state_dir)
    script_dir = os.path.dirname(os.path.abspath(depfile))
    initial_config = dict(
        DL_CACHE_DIR=dlcache,
        SCRIPT_DIR=script_dir,
        PROLOGUE="",
        WORKING_DIR=state_dir,
        EXECUTION_ID=_make_uuid(),
        ENV=dict(os.environ),
    )

    if config_file is not None:
        initial_config.update(load_config(config_file))

    return initial_config


def _not_callable(x):
    raise Exception("internal error")


from typing import Any, List
from jinja2 import Environment


class EvalContext:
    def __init__(self, rules: Rules, filename: str, hashcache, jinja2_env: Environment):
        self.rules = rules
        self.filename = filename
        self.hashcache = hashcache
        self.jinja2_env = jinja2_env

        __render_template = [_not_callable]
        _render_template = lambda x: __render_template[0](x)

        __render_template[0] = lambda x: render_template(
            rules.jinja2_env, x, rules.vars
        )
        config = LazyConfig(_render_template, rules.vars)
        self.eval_context = dict(rules=rules, config=config)
        self.config = config


def _eval_stmts(statements: List[Any], context: EvalContext):
    rules = context.rules
    root_dir = os.path.dirname(os.path.abspath(context.filename))

    def rt(x):
        return render_template(rules.jinja2_env, x, rules.vars)

    for dec in statements:
        if isinstance(dec, parser.RememberExecutedStmt):
            rules.add_remember_executed(dec)
        elif isinstance(dec, parser.IfStatement):
            _eval_if(dec, context)
        elif isinstance(dec, parser.AddIfMissingStatement):
            script_path = os.path.abspath(context.filename)
            script_dir = os.path.dirname(script_path)
            expanded_artifact = expand_dict(
                context.jinja2_env,
                dec.json_obj,
                context.config,
                SCRIPT_PATH=script_path,
                SCRIPT_DIR=script_dir,
            )
            rules.add_if_missing(expanded_artifact)
        elif isinstance(dec, parser.LetStatement):
            rules.set_var(dec.name, dec.value)
        elif isinstance(dec, parser.IncludeStatement):
            _filename = os.path.expanduser(dec.filename)
            statements = parser.parse(_filename)
            _eval_stmts(statements, context)
        elif isinstance(dec, parser.TypeDefStmt):
            rules.add_type(dec)
        elif isinstance(dec, parser.ExecProfileStmt):
            # would like to instantiate client here, but cannot because we don't have config fully populated yet.
            # do this after config is fully initialized
            rules.add_client(dec.name, dec.properties)
        elif isinstance(dec, parser.EvalStatement):
            exec(textwrap.dedent(dec.body), context.eval_context, context.eval_context)
        else:
            assert isinstance(dec, parser.Rule)

            inputs = _eval_rule(dec, rt, context.hashcache, root_dir, rules)

            dec.inputs = inputs

            dec.filename = context.filename
            if dec.outputs is None and dec.output_types is None:
                print(
                    f"Warning: rule {dec.name} has neither an output section nor an output_types section"
                )
            rules.set_rule(dec.name, dec)


def _eval_rule(dec, rt, hashcache, root_dir, rules):
    # rewrite any filerefs
    inputs = []
    for input in dec.inputs:
        if isinstance(input.json_obj, parser.FileRef):
            fileref = input.json_obj
            assert dec.filename
            script_dir = os.path.dirname(dec.filename)

            filename = os.path.abspath(os.path.join(script_dir, rt(fileref.filename)))
            # print(
            #     "re-anchoring",
            #     fileref.filename,
            #     "relative to",
            #     script_dir,
            #     "->",
            #     filename,
            # )
            ref_name = os.path.relpath(filename, root_dir)
            sha256 = hashcache.sha256(filename)
            new_json_obj = {
                "type": "$fileref",
                "name": ref_name,
                "filename": {"$filename": filename},
                "sha256": sha256,
            }
            rules.add_if_missing(new_json_obj)
            new_query_obj = {"type": "$fileref", "name": ref_name}
            # print("rewrite", filename, fileref.copy_to)
            input = parser.InputSpec(
                input.variable, new_query_obj, input.for_all, fileref.copy_to
            )
        inputs.append(input)

    # filerefs was a first attempt at making it easier to use scripts
    # attempt #2: uses_files. Process these in a similar way.
    for filename in dec.uses_files:
        # create a $fileref which has the destination field set
        filename = os.path.abspath(rt(filename))
        sha256 = hashcache.sha256(filename)
        new_json_obj = {
            "type": "$fileref",
            "name": filename,
            "sha256": sha256,
            "filename": {"$filename": filename},
            "destination": {"$value": filename},
        }
        rules.add_if_missing(new_json_obj)

        # mark this rule as dependant on this fileref
        new_query_obj = {"type": "$fileref", "name": filename}
        input = parser.InputSpec(
            "$fileref/{}".format(filename), new_query_obj, False, None
        )
        inputs.append(input)

    return inputs


def _eval_if(if_statement, context: EvalContext):
    condition_result = eval(
        if_statement.condition, context.eval_context, context.eval_context
    )
    if condition_result:
        _eval_stmts(if_statement.when_true, context)
    else:
        _eval_stmts(if_statement.when_false, context)


from .parser import ResolvedOutputType


def read_deps(filename, hashcache, jinja2_env, initial_vars={}) -> Rules:
    rules = Rules()
    for name, value in initial_vars.items():
        rules.set_var(name, value, is_override=True)

    statements = parser.parse(filename)
    context = EvalContext(rules, filename, hashcache, jinja2_env)
    _eval_stmts(statements, context)
    for _rule in rules.rule_by_name.values():
        if _rule.output_types is None:
            continue

        resolved_output_types = []
        for output_type in _rule.output_types:
            type_def_stmt = rules.types.get(output_type.type)
            if type_def_stmt is None:
                raise Exception(
                    f"Rule {_rule.name} referenced {output_type.type} in output_types, but that type is undefined"
                )
            resolved_output_types.append(
                ResolvedOutputType(type_def_stmt, output_type.cardinality)
            )
        _rule.resolved_output_types = resolved_output_types

    return rules


def read_rules(
    state_dir: str,
    depfile: str,
    config_file: Optional[str],
    jinja2_env,
    *,
    initial_config={},
) -> Rules:
    hashcache = HashCache(os.path.join(state_dir, "hashcache"))
    _initial_config = _load_initial_config(state_dir, depfile, config_file)
    for name, value in initial_config.items():
        # if name in _initial_config:
        log.warn(
            "Overriding %s with value %s (was %s)",
            name,
            value,
            _initial_config.get(name),
        )
        _initial_config[name] = value
    rules = read_deps(depfile, hashcache, jinja2_env, initial_vars=_initial_config)
    return rules


def get_staging_url(config):
    if "STAGING_URL" in config:
        return config["STAGING_URL"]
    return config["S3_STAGING_URL"]  # check this for backwards compatability
