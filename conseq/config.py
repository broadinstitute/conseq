import os

from conseq import parser
from conseq.template import create_jinja2_env


class Rules:
    def __init__(self):
        self.rule_by_name = {}
        self.vars = {}
        self.objs = []
        self.types = {}
        self.exec_clients = {}
        self.remember_executed = []
        self.jinja2_env = create_jinja2_env()

    def add_remember_executed(self, value):
        self.remember_executed.append(value)

    def add_if_missing(self, obj):
        self.objs.append(obj)

    def set_var(self, name, value):
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

    def get_client(self, name, must=True):
        if must:
            return self.exec_clients[name]
        else:
            return self.exec_clients.get(name)

    def add_type(self, typedef):
        name = typedef.name
        if name in self.types:
            raise Exception("Duplicate type for {}".format(name))
        self.types[name] = typedef

    def merge(self, other):
        for name, rule in other.rule_by_name.items():
            self.set_rule(name, rule)
        self.vars.update(other.vars)
        self.objs.extend(other.objs)
        self.exec_clients.update(other.exec_clients)
        self.remember_executed.extend(other.remember_executed)

        for t in other.types.values():
            self.types.add_type(t)

    def __repr__(self):
        return "<Rules vars:{}, rules:{}>".format(self.vars, list(self))


def load_config(config_file):
    config = {}

    p = parser.parse(os.path.expanduser(config_file))
    for dec in p:
        if isinstance(dec, parser.LetStatement):
            config[dec.name] = dec.value
        else:
            raise Exception("Initial config is only allowed to use 'let' statements but encountered {}".format(dec))

    return config


def _get_dlcache_dir(state_dir):
    dlcache = os.path.join(state_dir, 'dlcache')
    if not os.path.exists(dlcache):
        os.makedirs(dlcache)
    return dlcache


def _make_uuid():
    import uuid
    return uuid.uuid4().hex


def _load_initial_config(state_dir, depfile, config_file):
    dlcache = _get_dlcache_dir(state_dir)
    script_dir = os.path.dirname(os.path.abspath(depfile))
    initial_config = dict(DL_CACHE_DIR=dlcache,
                          SCRIPT_DIR=script_dir,
                          PROLOGUE="",
                          WORKING_DIR=state_dir,
                          EXECUTION_ID=_make_uuid(),
                          ENV=dict(os.environ))

    if config_file is not None:
        initial_config.update(load_config(config_file))

    return initial_config


def _eval_stmts(rules, statements, filename):
    for dec in statements:
        if isinstance(dec, parser.RememberExecutedStmt):
            rules.add_remember_executed(dec)
        elif isinstance(dec, parser.IfStatement):
            _eval_if(rules, dec, filename)
        elif isinstance(dec, parser.AddIfMissingStatement):
            rules.add_if_missing(dec.json_obj)
        elif isinstance(dec, parser.LetStatement):
            rules.set_var(dec.name, dec.value)
        elif isinstance(dec, parser.IncludeStatement):
            child_rules = read_deps(os.path.expanduser(dec.filename))
            rules.merge(child_rules)
        elif isinstance(dec, parser.TypeDefStmt):
            rules.add_type(dec)
        elif isinstance(dec, parser.ExecProfileStmt):
            # would like to instantiate client here, but cannot because we don't have config fully populated yet.
            # do this after config is fully initialized
            rules.add_client(dec.name, dec.properties)
        elif isinstance(dec, parser.EvalStatement):
            env = dict(rules=rules, config=rules.vars)
            exec(dec.body, env, env)
        else:
            assert isinstance(dec, parser.Rule)
            dec.filename = filename
            rules.set_rule(dec.name, dec)


def _eval_if(rules, if_statement, filename):
    assert if_statement.condition[1] == "=="
    if if_statement.condition[0] == if_statement.condition[2]:
        _eval_stmts(rules, if_statement.when_true, filename)
    else:
        _eval_stmts(rules, if_statement.when_false, filename)


def read_deps(filename, initial_vars={}):
    rules = Rules()
    for name, value in initial_vars.items():
        rules.set_var(name, value)

    statements = parser.parse(filename)
    _eval_stmts(rules, statements, filename)
    return rules


def read_rules(state_dir, depfile, config_file):
    initial_config = _load_initial_config(state_dir, depfile, config_file)

    rules = read_deps(depfile, initial_vars=initial_config)
    return rules
