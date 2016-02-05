import argparse
from . import depexec

def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument('file', metavar="FILE", help="the input file to parse")
    args = parser.parse_args()
    depexec.main(args.file)
