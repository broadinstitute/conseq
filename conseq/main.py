import argparse
import logging
import colorlog
from . import depexec

def rm(args):
    depexec.rm_cmd(args.dir, args.dry_run, args.json_query, args.with_invalidate)

def run(args):
    depexec.main(args.file, args.dir, args.targets, {}, args.concurrent)

def debugrun(args):
    depexec.debugrun(args.dir, args.file, args.target, {})

def dot(args):
    depexec.dot_cmd(args.dir, args.detailed)

def _list(args):
    depexec.list_cmd(args.dir)

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('--dir', metavar="DIR", help="The directory to write working versions of files to", default="state")
    parser.add_argument('--verbose', dest='verbose', action='store_true')
    parser.set_defaults(func=None)
    sub = parser.add_subparsers()

    run_cmd = sub.add_parser("run")
    run_cmd.add_argument('file', metavar="FILE", help="the input file to parse")
    run_cmd.add_argument("--concurrent", type=int, default=5)
    run_cmd.add_argument('targets', nargs='*')
    run_cmd.set_defaults(func=run)

    debugrun_cmd = sub.add_parser("debugrun")
    debugrun_cmd.add_argument('file', metavar="FILE", help="the input file to parse")
    debugrun_cmd.add_argument('target')
    debugrun_cmd.set_defaults(func=debugrun)

    dot_cmd = sub.add_parser("dot")
    dot_cmd.add_argument("--detailed", action="store_true")
    dot_cmd.set_defaults(func=dot)

    list_cmd = sub.add_parser("list")
    list_cmd.set_defaults(func=_list)

    rm_cmd = sub.add_parser("rm")
    rm_cmd.add_argument('--dry-run', action="store_true", dest="dry_run")
    rm_cmd.add_argument('--no-invalidate', action="store_false", dest="with_invalidate")
    rm_cmd.add_argument("json_query")
    rm_cmd.set_defaults(func=rm)

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

#    logging.basicConfig(level=level, format='%(asctime)s %(levelname)-4s: %(message)s',)
#    logger = logging.getLogger()
    if args.func != None:
        args.func(args)
