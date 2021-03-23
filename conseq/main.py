import argparse
import logging
import re

import colorlog

from conseq import commands
from conseq import depexec


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


def space(args):
    if args.name:
        depexec.select_space(args.dir, args.name, create_if_missing=args.new)
    else:
        depexec.print_spaces(args.dir)


def add_list(sub):
    parser = sub.add_parser("list", help="List all objects, executions, etc")

    def _list(args):
        commands.list_cmd(args.dir)

    parser.set_defaults(func=_list)


def add_space(sub):
    parser = sub.add_parser("space", help="Switch default space")
    parser.add_argument("name", nargs="?",
                        help="Name of space to use as the default.  If omitted, lists the names of all spaces")
    parser.add_argument("--new", "-n", action="store_true")
    parser.set_defaults(func=space)


def add_ls(sub):
    parser = sub.add_parser("ls", help="List artifacts")
    parser.add_argument('predicates', nargs='*', help="predicates to match in form 'key=value' ")
    parser.add_argument('--groupby', default='type')
    parser.add_argument('--columns')
    parser.add_argument('--space')

    def ls(args):
        key_value_pairs = [_parse_predicate_expr(p) for p in args.predicates]

        commands.ls_cmd(args.dir, args.space, key_value_pairs, args.groupby, args.columns)

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


def add_rm(sub):
    parser = sub.add_parser("rm", help="Remove objects that satisfy given query")
    parser.add_argument('--space')
    parser.add_argument('--dry-run', action="store_true", dest="dry_run")
    parser.add_argument('predicates', nargs='+', help="predicates to match in form 'key=value' ")

    def rm(args):
        commands.rm_cmd(args.dir, args.dry_run, args.space, _parse_query(args.predicates))

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
            "Expected variable assigment of the form \"var=value\" but got: {}".format(repr(txt)))
    return (m.group(1), m.group(2))


def _parse_label(label):
    m = re.match("([^=]+)=(.*)", label)
    if m is None:
        raise argparse.ArgumentTypeError(
            "Expected variable assigment of the form \"var=value\" but got: {}".format(repr(label)))
    return (m.group(1), {"$value": m.group(2)})


def add_run(sub):
    parser = sub.add_parser("run", help="Run rules in the specified file")
    parser.add_argument('file', metavar="FILE", help="the input file to parse")
    parser.add_argument('--define', "-D", action="append", type=_parse_define, dest="overrides")
    parser.add_argument("--concurrent", type=int, default=1)
    parser.add_argument("--nocapture", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--maxfail", type=int, default=1)
    parser.add_argument("--maxstart", type=int, default=None)
    parser.add_argument("--no-reattach", help="On startup, don't re-attach existing jobs", action="store_const", const=False, dest="reattach_existing")
    parser.add_argument("--reattach", help="On startup, re-attach existing jobs", action="store_const", const=True, dest="reattach_existing")
    parser.add_argument("--nothing", action="store_true",
                        help="Don't run anything (useful when re-attaching existing jobs but you don't want to run downstream steps)")
    parser.add_argument("--remove-unknown-artifacts", action="store_const", const=True, help="If set, don't ask before deleting artifacts which are not in the current conseq file.")
    parser.add_argument("--keep-unknown-artifacts", action="store_const", const=False, dest='remove_unknown_artifacts', help="If set, don't ask before deleting artifacts which are not in the current conseq file.")
    parser.add_argument("--addlabel", action="append", help="If set, will add the given property to each artifact generated from this run (Value must be of the form \"X=Y\")")
    parser.add_argument('targets', nargs='*', help="limit running to these rules and downstream rules")

    def run_cmd(args):
        concurrent = args.concurrent
        if args.nocapture:
            concurrent = 1

        overrides = {}
        if args.overrides is not None:
            overrides.update(args.overrides)

        print(args)
        if args.addlabel:
            print("addlabel", args.addlabel)
            properties_to_add = [_parse_label(x) for x in args.addlabel]
        else:
            properties_to_add = []

        return depexec.main(args.file, args.dir, args.targets, overrides, concurrent, not args.nocapture, args.confirm,
                            _get_config_file_path(args),
                            maxfail=args.maxfail, maxstart=args.maxstart,
                            force_no_targets=args.nothing,
                            reattach_existing=args.reattach_existing,
                            remove_unknown_artifacts=args.remove_unknown_artifacts,
                            properties_to_add=properties_to_add)

    parser.set_defaults(func=run_cmd)


def add_rules(sub):
    parser = sub.add_parser("rules", help="Print the names all rules in the file")
    parser.add_argument('file', metavar="FILE", help="the input file to parse")

    def rules(args):
        commands.print_rules(args.dir, args.file, _get_config_file_path(args))

    parser.set_defaults(func=rules)


def add_altdot(sub):
    parser = sub.add_parser("altdot", help="Print the names all rules in the file")
    parser.add_argument('file', metavar="FILE", help="the input file to parse")

    def altdot(args):
        commands.alt_dot(args.dir, args.file, _get_config_file_path(args))

    parser.set_defaults(func=altdot)


def add_superdot(sub):
    parser = sub.add_parser("superdot", help="Print the names all rules in the file")
    parser.add_argument('file', metavar="FILE", help="the input file to parse")

    def superdot(args):
        commands.superdot(args.dir, args.file, _get_config_file_path(args))

    parser.set_defaults(func=superdot)


def add_debugrun(sub):
    def debugrun(args):
        commands.debugrun(args.dir, args.file, args.target, {}, args.config)

    parser = sub.add_parser("debugrun",
                            help="perform query associated with a given target and report what matched (for debugging why rule doesn't run)")
    parser.add_argument('file', metavar="FILE", help="the input file to parse")
    parser.add_argument('target')
    parser.set_defaults(func=debugrun)


def add_dot(sub):
    def dot(args):
        commands.dot_cmd(args.dir, args.detailed)

    parser = sub.add_parser("dot", help="Write out a .dot file of the execution history")
    parser.add_argument("--detailed", action="store_true")
    parser.set_defaults(func=dot)


def add_report(sub):
    def report(args):
        commands.generate_report_cmd(args.dir, args.dest)
    parser = sub.add_parser("report", help="Generate HTML report describing the contents of the state directory")
    parser.add_argument("dest", help="the directory to write the html files to")
    parser.set_defaults(func=report)

def add_export(sub):
    def export(args):
        commands.export_cmd(args.dir, args.file, args.config, args.dest)

    parser = sub.add_parser("export", help="Write all artifacts to S3 so that they can be imported somewhere else")
    parser.add_argument("file", help="the conseq config to use")
    parser.add_argument("dest", help="the s3 path to write the index json file to")
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
        commands.localize_cmd(args.dir, args.space, _parse_query(args.predicates), args.file, _get_config_file_path(args))

    parser = sub.add_parser("localize", help="Download any artifacts with $file_url references")
    parser.add_argument('--space')
    parser.add_argument('file', metavar="FILE", help="the input file to parse")
    parser.add_argument('predicates', nargs='+', help="predicates to match in form 'key=value' ")
    parser.set_defaults(func=localize_cmd)

def add_downstream(sub):
    parser = sub.add_parser("downstream", help="List downstream artifacts")
    parser.add_argument('predicates', nargs='*', help="predicates to match in form 'key=value' ")
    parser.add_argument('--space')

    def downstream(args):
        key_value_pairs = [_parse_predicate_expr(p) for p in args.predicates]

        commands.downstream_cmd(args.dir, args.space, key_value_pairs)

    parser.set_defaults(func=downstream)

def conseq_command_entry():
    # disable stdout/stderr buffering to work better when run non-interactively
    import sys, io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, line_buffering=True)

    ret = main()
    if ret is not None:
        sys.exit(ret)


def main(args=None):
    from conseq import trace_on_demand
    trace_on_demand.install()

    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', metavar="DIR", help="The directory to write working versions of files to",
                        default="state")
    parser.add_argument('--verbose', dest='verbose', action='store_true')
    parser.add_argument('--config', help="Path to initial config", default="~/.conseq")
    parser.set_defaults(func=None)

    sub = parser.add_subparsers()
    add_list(sub)
    add_ls(sub)
    add_lsexec(sub)
    add_gc(sub)
    add_rm(sub)
    add_run(sub)
    add_rules(sub)
    add_debugrun(sub)
    add_dot(sub)
    add_altdot(sub)
    add_superdot(sub)
    add_history_cmd(sub)
    add_localize(sub)
    add_version(sub)
    add_export(sub)
    add_report(sub)
    add_downstream(sub)

    args = parser.parse_args(args)
    if args.verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    root = logging.getLogger()
    hdlr = logging.StreamHandler(None)
    hdlr.setFormatter(colorlog.ColoredFormatter('%(log_color)s%(asctime)s %(levelname)s: %(message)s'))
    root.addHandler(hdlr)
    root.setLevel(level)

    if args.func != None:
        return args.func(args)
    else:
        parser.print_help()
