import os
import textwrap
from typing import Optional

from conseq import parser
from conseq.hashcache import HashCache
from conseq.template import LazyConfig
from conseq.template import create_jinja2_env, render_template

import logging

log = logging.getLogger(__name__)


class Rules:
    def __init__(self):
        self.rule_by_name = {}
        self.vars = {}
        self.objs = []
        self.types = {}
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
                self.vars[name] = value

    def get_vars(self):
        return dict(self.vars)

    def __iter__(self):
        return iter(self.rule_by_name.values())

    def get_rule(self, name):
        return self.rule_by_name[name]

    def set_rule(self, name, rule):
        if name in self.rule_by_name:
            raise Exception("Duplicate rules for {}".format(name))
        self.rule_by_name[name] = rule

    def add_client(self, name, client):
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


def _eval_stmts(rules, statements, filename, hashcache, eval_context=None):
    root_dir = os.path.dirname(os.path.abspath(filename))

    if eval_context is None:
        # circular reference needed
        __render_template = [_not_callable]
        _render_template = lambda x: __render_template[0](x)
        config = LazyConfig(_render_template, rules.vars)
        __render_template[0] = lambda x: render_template(
            rules.jinja2_env, x, rules.vars
        )
        eval_context = dict(rules=rules, config=config)

    def rt(x):
        return render_template(rules.jinja2_env, x, rules.vars)

    for dec in statements:
        if isinstance(dec, parser.RememberExecutedStmt):
            rules.add_remember_executed(dec)
        elif isinstance(dec, parser.IfStatement):
            _eval_if(rules, dec, filename, eval_context, hashcache)
        elif isinstance(dec, parser.AddIfMissingStatement):
            rules.add_if_missing(dec.json_obj)
        elif isinstance(dec, parser.LetStatement):
            rules.set_var(dec.name, dec.value)
        elif isinstance(dec, parser.IncludeStatement):
            _filename = os.path.expanduser(dec.filename)
            statements = parser.parse(_filename)
            _eval_stmts(
                rules, statements, _filename, hashcache, eval_context=eval_context
            )
        elif isinstance(dec, parser.TypeDefStmt):
            rules.add_type(dec)
        elif isinstance(dec, parser.ExecProfileStmt):
            # would like to instantiate client here, but cannot because we don't have config fully populated yet.
            # do this after config is fully initialized
            rules.add_client(dec.name, dec.properties)
        elif isinstance(dec, parser.EvalStatement):
            exec(textwrap.dedent(dec.body), eval_context, eval_context)
        else:
            assert isinstance(dec, parser.Rule)

            inputs = _eval_rule(dec, rt, hashcache, root_dir, rules)

            dec.inputs = inputs

            dec.filename = filename
            rules.set_rule(dec.name, dec)

def _eval_rule(dec, rt, hashcache, root_dir, rules):
    # rewrite any filerefs
    inputs = []
    for input in dec.inputs:
        if isinstance(input.json_obj, parser.FileRef):
            fileref = input.json_obj
            assert dec.filename
            script_dir = os.path.dirname(dec.filename)

            filename = os.path.abspath(
                os.path.join(script_dir, rt(fileref.filename))
            )
            print(
                "re-anchoring",
                fileref.filename,
                "relative to",
                script_dir,
                "->",
                filename,
            )
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


def _eval_if(rules, if_statement, filename, eval_context, hashcache):
    condition_result = eval(if_statement.condition, eval_context, eval_context)
    if condition_result:
        _eval_stmts(rules, if_statement.when_true, filename, hashcache)
    else:
        _eval_stmts(rules, if_statement.when_false, filename, hashcache)


def read_deps(filename, hashcache, initial_vars={}) -> Rules:
    rules = Rules()
    for name, value in initial_vars.items():
        rules.set_var(name, value)

    statements = parser.parse(filename)
    _eval_stmts(rules, statements, filename, hashcache)
    return rules


def read_rules(
    state_dir: str, depfile: str, config_file: Optional[str], initial_config={}
) -> Rules:
    hashcache = HashCache(os.path.join(state_dir, "hashcache"))
    _initial_config = _load_initial_config(state_dir, depfile, config_file)
    _initial_config.update(initial_config)
    rules = read_deps(depfile, hashcache, initial_vars=_initial_config)
    return rules
