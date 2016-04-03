import argparse
import logging
import colorlog
from conseq import depexec, dep

def add_list(sub):
    parser = sub.add_parser("list", help="List all objects, executions, etc")
    parser.set_defaults(func=_list)

def _list(args):
    depexec.list_cmd(args.dir)

def add_ls(sub):
    parser = sub.add_parser("ls", help="List artifacts")
    parser.add_argument('predicates', nargs='*', help="predicates to match in form 'key=value' ")
    parser.add_argument('--groupby')
    parser.add_argument('--columns')
    parser.add_argument('--space', default=dep.PUBLIC_SPACE)
    parser.set_defaults(func=ls)

def ls(args):
    key_value_pairs = [p.split("=", maxsplit=1) for p in args.predicates]
    for pair in key_value_pairs:
        assert len(pair) == 2

    depexec.ls_cmd(args.dir, args.space, key_value_pairs, args.groupby, args.columns)

def add_gc(sub):
    parser = sub.add_parser("gc", help="Garbage collect (clean up unused files)")
    parser.set_defaults(func=gc)

def gc(args):
    depexec.gc(args.dir)

def add_rm(sub):
    parser = sub.add_parser("rm", help="Remove objects that satisfy given query")
    parser.add_argument('--dry-run', action="store_true", dest="dry_run")
    parser.add_argument('--no-invalidate', action="store_false", dest="with_invalidate")
    parser.add_argument('predicates', nargs='+', help="predicates to match in form 'key=value' ")
    parser.set_defaults(func=rm)

def rm(args):
    depexec.rm_cmd(args.dir, args.dry_run, args.json_query, args.with_invalidate)

def add_run(sub):
    parser = sub.add_parser("run", help="Run rules in the specified file")
    parser.add_argument('file', metavar="FILE", help="the input file to parse")
    parser.add_argument("--concurrent", type=int, default=5)
    parser.add_argument("--nocapture", action="store_true")
    parser.add_argument("--confirm", action="store_true")
    parser.add_argument('targets', nargs='*')
    parser.set_defaults(func=run)

def run(args):
    concurrent = args.concurrent
    if args.nocapture:
        concurrent = 1
    depexec.main(args.file, args.dir, args.targets, {}, concurrent, not args.nocapture, args.confirm)

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
    depexec.debugrun(args.dir, args.file, args.target, {})

def add_dot(sub):
    parser = sub.add_parser("dot", help="Write out a .dot file of the execution history")
    parser.add_argument("--detailed", action="store_true")
    parser.set_defaults(func=dot)

def dot(args):
    depexec.dot_cmd(args.dir, args.detailed)

def add_export(sub):
    parser = sub.add_parser("export", help="export all artifacts to S3")
    parser.add_argument("url", help="should be of the form s3://bucket/path")
    parser.set_defaults(func=export)

def export(args):
    from conseq import export_cmd
    export_cmd.export(args.dir, args.url)

def add_import(sub):
    parser = sub.add_parser("import", help="import artifacts from S3")
    parser.add_argument("url", help="should be of the form s3://bucket/path")
    parser.set_defaults(func=_import)

def _import(args):
    from conseq import export_cmd
    export_cmd.import_artifacts(args.dir, args.url)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', metavar="DIR", help="The directory to write working versions of files to", default="state")
    parser.add_argument('--verbose', dest='verbose', action='store_true')
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












