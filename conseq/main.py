import argparse
import logging
import re

import colorlog

from conseq import commands
from conseq import depexec
from conseq.types import Obj
import os

class RegExpMatch:
    def __init__(self, pattern):
        self.pattern = re.compile(pattern)

    def match(self, v):
        return self.pattern.match(v)


def _parse_predicate_expr(txt):
    m = re.match("^([^=~]+)(.)(.*)$", txt)
    assert m != None, "expect an object filter, but got %s" % repr(txt)
    name = m.group(1)
    op = m.group(2)
    value = m.group(3)
    if op == "=":
        return (name, value)
    else:
        return (name, RegExpMatch(value))


def _parse_query(predicates):
    query = {}
    for pair in predicates:
        name, value = _parse_predicate_expr(pair)
        query[name] = value
    return query


def add_list(sub):
    parser = sub.add_parser("list", help="List all objects, executions, etc")

    def _list(args):
        commands.list_cmd(args.dir)

    parser.set_defaults(func=_list)



def add_ls(sub):
    parser = sub.add_parser("ls", help="List artifacts")
    parser.add_argument(
        "predicates", nargs="*", help="predicates to match in form 'key=value' "
    )
    parser.add_argument("--groupby", default="type")
    parser.add_argument(
        "--columns", help="List of columns to show (specify as a comma separated list)"
    )
    parser.add_argument("--space")

    def ls(args):
        key_value_pairs = [_parse_predicate_expr(p) for p in args.predicates]

        columns = None
        if args.columns:
            columns = args.columns.split(",")
        commands.ls_cmd(args.dir, args.space, key_value_pairs, args.groupby, columns)

    parser.set_defaults(func=ls)


def add_gc(sub):
    parser = sub.add_parser("gc", help="Garbage collect (clean up unused files)")

    def gc(args):
        commands.gc(args.dir)

    parser.set_defaults(func=gc)


def add_lsexec(sub):
    parser = sub.add_parser("lsexec", help="List executions")

    def lsexec(args):
        commands.lsexec(args.dir)

    parser.set_defaults(func=lsexec)


def add_forget(sub):
    parser = sub.add_parser(
        "forget", help="Remove records of execution having been completed"
    )
    parser.add_argument("--regex", action="store_true", dest="is_pattern")
    parser.add_argument("rule_name")

    def forget(args):
        commands.forget_cmd(args.dir, args.rule_name, args.is_pattern)

    parser.set_defaults(func=forget)


def add_rm(sub):
    parser = sub.add_parser("rm", help="Remove objects that satisfy given query")
    parser.add_argument("--space")
    parser.add_argument("--dry-run", action="store_true", dest="dry_run")
    parser.add_argument(
        "predicates", nargs="+", help="predicates to match in form 'key=value' "
    )

    def rm(args):
        commands.rm_cmd(
            args.dir, args.dry_run, args.space, _parse_query(args.predicates)
        )

    parser.set_defaults(func=rm)


def _get_config_file_path(args):
    import os

    config_file = os.path.expanduser(args.config)
    if not os.path.exists(config_file):
        config_file = None
    return config_file


def _parse_define(txt):
    m = re.match("([^=]+)=(.*)", txt)
    if m is None:
        raise argparse.ArgumentTypeError(
            'Expected variable assigment of the form "var=value" but got: {}'.format(
                repr(txt)
            )
        )
    return (m.group(1), m.group(2))


def _parse_label(label):
    m = re.match("([^=]+)=(.*)", label)
    if m is None:
        raise argparse.ArgumentTypeError(
            'Expected variable assigment of the form "var=value" but got: {}'.format(
                repr(label)
            )
        )
    return (m.group(1), {"$value": m.group(2)})


from typing import Callable, Sequence, Tuple
from collections import namedtuple

InputMatchExpression = namedtuple("InputMatchExpression", "varname property value")

# TODO: Add support for specifying filter on inputs as well
# write documentation giving example of running rule on a single artifact
# process_model_config
# !process_model_config data:label=Avana
def _parse_rule_filters(
    filename: str,
) -> Callable[[Sequence[Tuple[str, "Obj"]], str], bool]:
    # file is a list of rule name regexps to skip
    # if prefixed with "!" it means override the skip and run it

    # list of tuples in the form: (is_include, name)
    rule_filters = []

    # each filter consists of the following parts:
    # 1. if prefixed with "!" it is an inclusion, not exclusion
    # 2. up to the first whitespace, it's a regex for the rule name
    # 3. (optional) a variable:property=value which can be used as an additional filter
    filter_pattern = re.compile("(!?)(\\S+)(?:\\s+([^:]+):([^=]+)=(\\S+))?\\s*")

    with open(filename, "rt") as fd:
        for line in fd.readlines():
            line = line.strip()
            if line.startswith("#") or line == "":
                continue

            is_include = False

            m = filter_pattern.match(line)
            if m is None:
                raise Exception(
                    f"Could not parse line in filter file {filename}: {line}"
                )

            include_char, rule_name, var_name, prop_name, value = m.groups()

            if include_char == "!":
                is_include = True

            if var_name is not None:
                input_exp = InputMatchExpression(var_name, prop_name, value)
            else:
                input_exp = None

            rule_filters.append((is_include, re.compile(rule_name), input_exp))

    from conseq.dep import Obj

    def inputs_match(
        inputs: Sequence[Tuple[str, Obj]], input_exp: InputMatchExpression
    ) -> bool:
        for varname, artifact in inputs:
            if input_exp.varname != varname:
                continue

            input_prop_value = artifact.get(input_exp.property)
            if input_prop_value == input_exp.value:
                return True

        return False

    def is_allowed_name(inputs, name):
        allowed = True
        for is_include, name_exp, input_exp in rule_filters:
            if name_exp.match(name) and (
                input_exp is None or inputs_match(inputs, input_exp)
            ):
                if is_include:
                    allowed = True
                else:
                    allowed = False
        return allowed

    return is_allowed_name


def add_run(sub):
    parser = sub.add_parser("run", help="Run rules in the specified file")
    parser.add_argument("file", metavar="FILE", help="the input file to parse")
    parser.add_argument(
        "--define", "-D", action="append", type=_parse_define, dest="overrides"
    )
    parser.add_argument("--concurrent", type=int, default=1)
    parser.add_argument("--nocapture", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--maxfail", type=int, default=1)
    parser.add_argument("--maxstart", type=int, default=None)
    parser.add_argument(
        "--no-reattach",
        help="On startup, don't re-attach existing jobs",
        action="store_const",
        const=False,
        dest="reattach_existing",
    )
    parser.add_argument(
        "--reattach",
        help="On startup, re-attach existing jobs",
        action="store_const",
        const=True,
        dest="reattach_existing",
    )
    parser.add_argument(
        "--nothing",
        action="store_true",
        help="Don't run anything (useful when re-attaching existing jobs but you don't want to run downstream steps)",
    )
    parser.add_argument(
        "--remove-unknown-artifacts",
        action="store_const",
        const=True,
        help="If set, don't ask before deleting artifacts which are not in the current conseq file.",
    )
    parser.add_argument(
        "--keep-unknown-artifacts",
        action="store_const",
        const=False,
        dest="remove_unknown_artifacts",
        help="If set, don't ask before deleting artifacts which are not in the current conseq file.",
    )
    parser.add_argument(
        "--addlabel",
        action="append",
        help='If set, will add the given property to each artifact generated from this run (Value must be of the form "X=Y")',
    )
    parser.add_argument(
        "--rulefilter", help="If set, will read this as a file of which rules to run"
    )
    parser.add_argument(
        "targets", nargs="*", help="limit running to these rules and downstream rules"
    )

    def run_cmd(args):
        concurrent = args.concurrent
        if args.nocapture:
            concurrent = 1

        overrides = {}
        if args.overrides is not None:
            overrides.update(args.overrides)

        #        print(args)
        if args.addlabel:
            print("addlabel", args.addlabel)
            properties_to_add = [_parse_label(x) for x in args.addlabel]
        else:
            properties_to_add = []

        if args.rulefilter:
            rule_filter = _parse_rule_filters(args.rulefilter)
        else:
            rule_filter = None

        return depexec.main(
            args.file,
            args.dir,
            args.targets,
            overrides,
            concurrent,
            not args.nocapture,
            args.confirm,
            _get_config_file_path(args),
            maxfail=args.maxfail,
            maxstart=args.maxstart,
            force_no_targets=args.nothing,
            reattach_existing=args.reattach_existing,
            remove_unknown_artifacts=args.remove_unknown_artifacts,
            properties_to_add=properties_to_add,
            rule_filter=rule_filter,
        )

    parser.set_defaults(func=run_cmd)


def add_rules(sub):
    parser = sub.add_parser("rules", help="Print the names all rules in the file")
    parser.add_argument("file", metavar="FILE", help="the input file to parse")
    parser.add_argument(
        "--up",
        metavar="RULE",
        help="If specified, will report only rules upstream of the given rule",
    )
    parser.add_argument(
        "--down",
        metavar="RULE",
        help="If specified, will report only rules downstream of the given rule",
    )

    def rules(args):
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
            args.dir, args.file, _get_config_file_path(args), mode, rule_name
        )

    parser.set_defaults(func=rules)

def add_debugrun(sub):
    def debugrun(args):
        config_path = _get_config_file_path(args)
        commands.debugrun(args.dir, args.file, args.rule, {}, config_path )

    parser = sub.add_parser(
        "debugrun",
        help="perform query associated with a given rule and report what matched (for debugging why rule doesn't run)",
    )
    parser.add_argument("file", metavar="FILE", help="the input file to parse")
    parser.add_argument("rule", help="the name of the rule to attempt to run")
    parser.set_defaults(func=debugrun)


def add_report(sub):
    def report(args):
        from .report import generate_report_cmd

        generate_report_cmd(args.dir, args.dest)

    parser = sub.add_parser(
        "report",
        help="Generate HTML report describing the contents of the state directory",
    )
    parser.add_argument("dest", help="the directory to write the html files to")
    parser.set_defaults(func=report)


def add_export(sub):
    def export(args):
        if args.exclude_patterns:
            exclude_patterns = args.exclude_patterns
        else:
            exclude_patterns = []

        commands.export_cmd(
            args.dir, args.file, _get_config_file_path(args), args.dest, exclude_patterns
        )

    parser = sub.add_parser(
        "export",
        help="Write all artifacts to S3 so that they can be imported somewhere else",
    )
    parser.add_argument("file", help="the conseq config to use")
    parser.add_argument(
        "dest",
        help="the path to write the index json file to. (If it starts with s3://.. it will upload to an s3 path)",
    )
    parser.add_argument(
        "--exclude-remember",
        help="regexp of rule names to skip in the export (can be specified multiple times)",
        dest="exclude_patterns",
        action="append",
    )
    parser.set_defaults(func=export)


def history_cmd(args):
    commands.print_history(args.dir)


def add_version(sub):
    def version_cmd(args):
        import conseq

        print(conseq.__version__)

    parser = sub.add_parser("version", help="prints version")
    parser.set_defaults(func=version_cmd)


def add_history_cmd(sub):
    parser = sub.add_parser("history", help="Print the history of all executions")
    parser.set_defaults(func=history_cmd)


def add_localize(sub):
    def localize_cmd(args):
        commands.localize_cmd(
            args.dir,
            args.space,
            _parse_query(args.predicates),
            args.file,
            _get_config_file_path(args),
        )

    parser = sub.add_parser(
        "localize", help="Download any artifacts with $file_url references"
    )
    parser.add_argument("--space")
    parser.add_argument("file", metavar="FILE", help="the input file to parse")
    parser.add_argument(
        "predicates", nargs="+", help="predicates to match in form 'key=value' "
    )
    parser.set_defaults(func=localize_cmd)


def add_downstream(sub):
    parser = sub.add_parser("downstream", help="List downstream artifacts")
    parser.add_argument(
        "predicates", nargs="*", help="predicates to match in form 'key=value' "
    )
    parser.add_argument("--space")

    def downstream(args):
        key_value_pairs = [_parse_predicate_expr(p) for p in args.predicates]

        commands.downstream_cmd(args.dir, args.space, key_value_pairs)

    parser.set_defaults(func=downstream)


def add_stage(sub):
    parser = sub.add_parser(
        "stage",
        help="Stage inputs for a rule and create a test harness for running rule",
    )
    parser.add_argument(
        "export_file",
        help="Path to export of full pipeline run to select artifacts from",
    )
    parser.add_argument(
        "rule_file", help="File containing conseq rules to create test harness for"
    )
    parser.add_argument("dest_dir", help="directory to write test harness to")

    def stage(args):
        commands.stage_cmd(args.export_file, args.rule_file, args.dest_dir)

    parser.set_defaults(func=stage)


def conseq_command_entry():
    # disable stdout/stderr buffering to work better when run non-interactively
    import sys, io

    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, line_buffering=True)

    ret = main()
    if ret is not None:
        sys.exit(ret)


def main(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--dir",
        metavar="DIR",
        help="The directory to write working versions of files to",
        default="state",
    )
    parser.add_argument("--verbose", dest="verbose", action="store_true")
    parser.add_argument("--config", help="Path to initial config", default=os.path.expanduser("~/.conseq"))
    parser.set_defaults(func=None)

    sub = parser.add_subparsers()
    add_list(sub)
    add_ls(sub)
    add_lsexec(sub)
    add_gc(sub)
    add_rm(sub)
    add_forget(sub)
    add_run(sub)
    add_rules(sub)
    add_debugrun(sub)
    add_history_cmd(sub)
    add_localize(sub)
    add_version(sub)
    add_export(sub)
    add_report(sub)
    add_downstream(sub)
    add_stage(sub)

    args = parser.parse_args(args)
    if args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    root = logging.getLogger()
    hdlr = logging.StreamHandler(None)
    hdlr.setFormatter(
        colorlog.ColoredFormatter("%(log_color)s%(asctime)s %(levelname)s: %(message)s")
    )
    root.addHandler(hdlr)
    root.setLevel(level)

    if args.func != None:
        return args.func(args)
    else:
        parser.print_help()
