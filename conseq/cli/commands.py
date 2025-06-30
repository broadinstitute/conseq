import argparse
import re
import logging
from typing import Callable, Sequence, Tuple, Dict, Any, Optional, List
from collections import namedtuple

from conseq import commands
from conseq import depexec
from conseq.types import Obj

# Utility functions

class RegExpMatch:
    def __init__(self, pattern):
        self.pattern = re.compile(pattern)

    def match(self, v):
        return self.pattern.match(v)


def parse_predicate_expr(txt):
    m = re.match("^([^=~]+)(.)(.*)$", txt)
    assert m != None, "expect an object filter, but got %s" % repr(txt)
    name = m.group(1)
    op = m.group(2)
    value = m.group(3)
    if op == "=":
        return (name, value)
    else:
        return (name, RegExpMatch(value))


def parse_query(predicates):
    query = {}
    for pair in predicates:
        name, value = parse_predicate_expr(pair)
        query[name] = value
    return query


def get_config_file_path(args):
    import os
    config_file = os.path.expanduser(args.config)
    if not os.path.exists(config_file):
        config_file = None
    return config_file


def parse_define(txt):
    m = re.match("([^=]+)=(.*)", txt)
    if m is None:
        raise argparse.ArgumentTypeError(
            'Expected variable assigment of the form "var=value" but got: {}'.format(
                repr(txt)
            )
        )
    return (m.group(1), m.group(2))


def parse_label(label):
    m = re.match("([^=]+)=(.*)", label)
    if m is None:
        raise argparse.ArgumentTypeError(
            'Expected variable assigment of the form "var=value" but got: {}'.format(
                repr(label)
            )
        )
    return (m.group(1), {"$value": m.group(2)})


InputMatchExpression = namedtuple("InputMatchExpression", "varname property value")


# Command handler functions

def list_cmd(args):
    commands.list_cmd(args.dir)


def ls_cmd(args):
    key_value_pairs = [parse_predicate_expr(p) for p in args.predicates]

    columns = None
    if args.columns:
        columns = args.columns.split(",")
    commands.ls_cmd(args.dir, args.space, key_value_pairs, args.groupby, columns)


def gc_cmd(args):
    commands.gc(args.dir)


def lsexec_cmd(args):
    commands.lsexec(args.dir)


def forget_cmd(args):
    commands.forget_cmd(args.dir, args.rule_name, args.is_pattern)


def rm_cmd(args):
    commands.rm_cmd(
        args.dir, args.dry_run, args.space, parse_query(args.predicates)
    )


def run_cmd(args):
    concurrent = args.concurrent
    if args.nocapture:
        concurrent = 1

    overrides = {}
    if args.overrides is not None:
        overrides.update(args.overrides)

    if args.addlabel:
        properties_to_add = [parse_label(x) for x in args.addlabel]
    else:
        properties_to_add = []

    return depexec.main(
        args.file,
        args.dir,
        args.targets,
        overrides,
        concurrent,
        not args.nocapture,
        args.confirm,
        get_config_file_path(args),
        maxfail=args.maxfail,
        maxstart=args.maxstart,
        force_no_targets=args.nothing,
        reattach_existing=args.reattach_existing,
        remove_unknown_artifacts=args.remove_unknown_artifacts,
        properties_to_add=properties_to_add,
    )


def rules_cmd(args):
    if args.up is None and args.down is None:
        mode = "all"
        rule_name = None
    else:
        assert (
            args.up is None or args.down is None
        ), "Cannot specify both --up and --down"
        if args.up:
            mode = "up"
            rule_name = args.up
        else:
            mode = "down"
            rule_name = args.down

    commands.print_rules(
        args.dir, args.file, get_config_file_path(args), mode, rule_name
    )


def debugrun_cmd(args):
    config_path = get_config_file_path(args)
    commands.debugrun(
        args.dir, args.file, args.rule, {}, config_path, args.save_inputs_filename
    )


def report_cmd(args):
    from conseq.report import generate_report_cmd
    generate_report_cmd(args.dir, args.dest)


def export_cmd(args):
    if args.exclude_patterns:
        exclude_patterns = args.exclude_patterns
    else:
        exclude_patterns = []

    commands.export_cmd(
        args.dir,
        args.file,
        get_config_file_path(args),
        args.dest,
        exclude_patterns,
    )


def history_cmd(args):
    commands.print_history(args.dir)


def version_cmd(args):
    import conseq
    print(conseq.__version__)


def localize_cmd(args):
    commands.localize_cmd(
        args.dir,
        args.space,
        parse_query(args.predicates),
        args.file,
        get_config_file_path(args),
    )


def downstream_cmd(args):
    key_value_pairs = [parse_predicate_expr(p) for p in args.predicates]
    commands.downstream_cmd(args.dir, args.space, key_value_pairs)


def stage_cmd(args):
    commands.stage_cmd(args.export_file, args.rule_file, args.output_script)
