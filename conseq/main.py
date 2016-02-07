import argparse
from . import depexec

def rm(args):
    depexec.rm_cmd(args.dir, args.dry_run, args.json_query, args.with_invalidate)

def run(args):
    depexec.main(args.file, args.dir)

def dot(args):
    depexec.dot_cmd(args.dir)

def _list(args):
    depexec.list_cmd(args.dir)

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', metavar="DIR", help="The directory to write working versions of files to", default="state")

    sub = parser.add_subparsers()

    run_cmd = sub.add_parser("run")
    run_cmd.add_argument('file', metavar="FILE", help="the input file to parse")
    run_cmd.set_defaults(func=run)

    dot_cmd = sub.add_parser("dot")
    dot_cmd.set_defaults(func=dot)

    list_cmd = sub.add_parser("list")
    list_cmd.set_defaults(func=_list)

    rm_cmd = sub.add_parser("rm")
    rm_cmd.add_argument('--dry-run', action="store_true", dest="dry_run")
    rm_cmd.add_argument('--no-invalidate', action="store_false", dest="with_invalidate")
    rm_cmd.add_argument("json_query")
    rm_cmd.set_defaults(func=rm)

    args = parser.parse_args()
    args.func(args)
