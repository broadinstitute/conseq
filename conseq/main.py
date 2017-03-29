import argparse
import logging
import colorlog
from conseq import depexec, dep

import re

class RegExpMatch:
    def __init__(self, pattern):
        self.pattern = re.compile(pattern)

    def match(self, v):
        return self.pattern.match(v)


def add_list(sub):
    parser = sub.add_parser("list", help="List all objects, executions, etc")
    parser.set_defaults(func=_list)

def _list(args):
    depexec.list_cmd(args.dir)

def space(args):
    if args.name:
        depexec.select_space(args.dir, args.name, create_if_missing=args.new)
    else:
        depexec.print_spaces(args.dir)

def add_space(sub):
    parser = sub.add_parser("space", help="Switch default space")
    parser.add_argument("name", nargs="?", help="Name of space to use as the default.  If omitted, lists the names of all spaces")
    parser.add_argument("--new", "-n", action="store_true")
    parser.set_defaults(func=space)

def add_ls(sub):
    parser = sub.add_parser("ls", help="List artifacts")
    parser.add_argument('predicates', nargs='*', help="predicates to match in form 'key=value' ")
    parser.add_argument('--groupby', default='type')
    parser.add_argument('--columns')
    parser.add_argument('--space')
    parser.set_defaults(func=ls)


def ls(args):
    key_value_pairs = [_parse_predicate_expr(p) for p in args.predicates]

    depexec.ls_cmd(args.dir, args.space, key_value_pairs, args.groupby, args.columns)

def add_gc(sub):
    parser = sub.add_parser("gc", help="Garbage collect (clean up unused files)")
    parser.set_defaults(func=gc)

def gc(args):
    depexec.gc(args.dir)

def add_rm(sub):
    parser = sub.add_parser("rm", help="Remove objects that satisfy given query")
    parser.add_argument('--space')
    parser.add_argument('--dry-run', action="store_true", dest="dry_run")
    parser.add_argument('--no-invalidate', action="store_false", dest="with_invalidate")
    parser.add_argument('predicates', nargs='+', help="predicates to match in form 'key=value' ")
    parser.set_defaults(func=rm)

def _parse_predicate_expr(txt):
    m = re.match("^([^=~]+)(.)(.*)$", txt)
    assert m != None
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

def rm(args):
    depexec.rm_cmd(args.dir, args.dry_run, args.space, _parse_query(args.predicates), False)

def add_run(sub):
    parser = sub.add_parser("run", help="Run rules in the specified file")
    parser.add_argument('file', metavar="FILE", help="the input file to parse")
    parser.add_argument("--concurrent", type=int, default=1)
    parser.add_argument("--nocapture", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument("--maxfail", type=int, default=1)
    parser.add_argument("--maxstart", type=int, default=None)
    parser.add_argument('--refresh_xrefs', help='refresh xrefs', action="store_true")
    parser.add_argument('targets', nargs='*')
    parser.set_defaults(func=run_cmd)

def run_cmd(args):
    concurrent = args.concurrent
    if args.nocapture:
        concurrent = 1

    import os
    config_file = os.path.expanduser(args.config)
    if not os.path.exists(config_file):
        config_file = None

    depexec.main(args.file, args.dir, args.targets, {}, concurrent, not args.nocapture, args.confirm, config_file,
                 refresh_xrefs=args.refresh_xrefs, maxfail=args.maxfail, maxstart=args.maxstart)

def add_rules(sub):
    parser = sub.add_parser("rules", help="Print the names all rules in the file")
    parser.add_argument('file', metavar="FILE", help="the input file to parse")
    parser.set_defaults(func=rules)

def rules(args):
    depexec.print_rules(args.file)

def add_debugrun(sub):
    parser = sub.add_parser("debugrun", help="perform query associated with a given target and report what matched (for debugging why rule doesn't run)")
    parser.add_argument('file', metavar="FILE", help="the input file to parse")
    parser.add_argument('target')
    parser.set_defaults(func=debugrun)

def debugrun(args):
    depexec.debugrun(args.dir, args.file, args.target, {}, args.config)

def add_dot(sub):
    parser = sub.add_parser("dot", help="Write out a .dot file of the execution history")
    parser.add_argument("--detailed", action="store_true")
    parser.set_defaults(func=dot)

def dot(args):
    depexec.dot_cmd(args.dir, args.detailed)

def add_export_conseq(sub):
    parser = sub.add_parser("export-conseq", help="export artifacts as a conseq file")
    parser.add_argument("--out", help="Name of file to write output to. Otherwise writes to stdout")
    parser.add_argument("--upload", help="Path to upload files so that they will be accessible on a different machine.  Should be of the form s3://bucket/prefix/CAS")
    parser.set_defaults(func=export_conseq)

def export_conseq(args):
    from conseq import export_cmd
    export_cmd.export_conseq(args.dir, args.out, args.upload)

    #export_meta

def add_export(sub):
    parser = sub.add_parser("export", help="export all artifacts to S3")
    parser.add_argument("url", help="should be of the form s3://bucket/path")
    parser.set_defaults(func=export)

def export(args):
    from conseq import export_cmd
    export_cmd.export_artifacts(args.dir, args.url, args.config)

def add_import(sub):
    parser = sub.add_parser("import", help="import artifacts from S3")
    parser.add_argument("url", help="should be of the form s3://bucket/path")
    parser.set_defaults(func=_import)

def _import(args):
    from conseq import export_cmd
    export_cmd.import_artifacts(args.dir, args.url, args.config)

def history_cmd(args):
    depexec.print_history(args.dir)

def add_history_cmd(sub):
    parser = sub.add_parser("history", help="Print the history of all executions")
    parser.set_defaults(func=history_cmd)

def localize_cmd(args):
    depexec.localize_cmd(args.dir, args.space, _parse_query(args.predicates), args.file, args.config)

def add_localize(sub):
    parser = sub.add_parser("localize", help="Download any artifacts with $file_url references")
    parser.add_argument('--space')
    parser.add_argument('file', metavar="FILE", help="the input file to parse")
    parser.add_argument('predicates', nargs='+', help="predicates to match in form 'key=value' ")
    parser.set_defaults(func=localize_cmd)

def main():
    from conseq import trace_on_demand
    trace_on_demand.install()

    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', metavar="DIR", help="The directory to write working versions of files to", default="state")
    parser.add_argument('--verbose', dest='verbose', action='store_true')
    parser.add_argument('--config', help="Path to initial config", default="~/.conseq")
    parser.set_defaults(func=None)

    sub = parser.add_subparsers()
    add_list(sub)
    add_ls(sub)
    add_gc(sub)
    add_rm(sub)
    add_run(sub)
    add_rules(sub)
    add_debugrun(sub)
    add_dot(sub)
    add_export(sub)
    add_import(sub)
    add_space(sub)
    add_export_conseq(sub)
    add_history_cmd(sub)
    add_localize(sub)

    args = parser.parse_args()
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
        args.func(args)
    else:
        parser.print_help()












