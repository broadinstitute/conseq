import logging
import os
import pdb
import sys
import io

import colorlog

from conseq.cli.parser import ConseqArgumentParser

def conseq_command_entry():
    """Entry point for the conseq command-line tool"""
    # disable stdout/stderr buffering to work better when run non-interactively
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, line_buffering=True)
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, line_buffering=True)

    ret = main()
    if ret is not None:
        sys.exit(ret)

def main(args=None):
    """Main function for the conseq command-line tool"""
    # Create and configure the argument parser
    parser = ConseqArgumentParser()
    args = parser.parse_args(args)
    
    # Configure logging
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

    # Execute the command if one was specified
    if args.func is not None:
        if args.pdb:
            try:
                return args.func(args)
            except:
                pdb.post_mortem()
        else:
            return args.func(args)
    else:
        parser.parser.print_help()
