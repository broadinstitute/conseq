import argparse
import os
from typing import Optional, List, Any

from conseq.cli.commands import (
    list_cmd,
    ls_cmd,
    gc_cmd,
    lsexec_cmd,
    forget_cmd,
    rm_cmd,
    run_cmd,
    rules_cmd,
    debugrun_cmd,
    report_cmd,
    export_cmd,
    history_cmd,
    version_cmd,
    localize_cmd,
    downstream_cmd,
    stage_cmd,
    parse_define,
    parse_rule_filters,
    parse_label,
)
from conseq.static_analysis.model import createDAG


class ConseqArgumentParser:
    """Handles setting up the command-line argument parser for conseq"""

    def __init__(self):
        self.parser = argparse.ArgumentParser()
        self._setup_main_parser()
        self._setup_subparsers()

    def _setup_main_parser(self):
        """Set up the main parser with common arguments"""
        self.parser.add_argument(
            "--dir",
            metavar="DIR",
            help="The directory to write working versions of files to",
            default="state",
        )
        self.parser.add_argument(
            "--pdb",
            action="store_true",
            help="Run inside of pdb so that the debugger is started on exception",
        )
        self.parser.add_argument("--verbose", dest="verbose", action="store_true")
        self.parser.add_argument(
            "--config",
            help="Path to initial config",
            default=os.path.expanduser("~/.conseq"),
        )
        self.parser.set_defaults(func=None)

    def _add_analyze(self, sub):
        """Add the analyze command to the parser"""
        parser = sub.add_parser(
            "analyze", help="Analyze a conseq file and print its dependency graph",
        )
        parser.add_argument("file", metavar="FILE", help="the conseq file to analyze")
        parser.set_defaults(func=self._analyze_cmd)

    def _analyze_cmd(self, args):
        """Command handler for the analyze command"""
        from ..static_analysis.analyze import analyze

        analyze(args.file, args.dir)

    def _setup_subparsers(self):
        """Set up all subparsers for the different commands"""
        sub = self.parser.add_subparsers()
        self._add_list(sub)
        self._add_ls(sub)
        self._add_lsexec(sub)
        self._add_gc(sub)
        self._add_rm(sub)
        self._add_forget(sub)
        self._add_run(sub)
        self._add_rules(sub)
        self._add_debugrun(sub)
        self._add_history_cmd(sub)
        self._add_localize(sub)
        self._add_version(sub)
        self._add_export(sub)
        self._add_report(sub)
        self._add_downstream(sub)
        self._add_stage(sub)
        self._add_analyze(sub)

    def _add_list(self, sub):
        parser = sub.add_parser("list", help="List all objects, executions, etc")
        parser.set_defaults(func=list_cmd)

    def _add_ls(self, sub):
        parser = sub.add_parser("ls", help="List artifacts")
        parser.add_argument(
            "predicates", nargs="*", help="predicates to match in form 'key=value' "
        )
        parser.add_argument("--groupby", default="type")
        parser.add_argument(
            "--columns",
            help="List of columns to show (specify as a comma separated list)",
        )
        parser.add_argument("--space")
        parser.set_defaults(func=ls_cmd)

    def _add_gc(self, sub):
        parser = sub.add_parser("gc", help="Garbage collect (clean up unused files)")
        parser.set_defaults(func=gc_cmd)

    def _add_lsexec(self, sub):
        parser = sub.add_parser("lsexec", help="List executions")
        parser.set_defaults(func=lsexec_cmd)

    def _add_forget(self, sub):
        parser = sub.add_parser(
            "forget", help="Remove records of execution having been completed"
        )
        parser.add_argument("--regex", action="store_true", dest="is_pattern")
        parser.add_argument("rule_name")
        parser.set_defaults(func=forget_cmd)

    def _add_rm(self, sub):
        parser = sub.add_parser("rm", help="Remove objects that satisfy given query")
        parser.add_argument("--space")
        parser.add_argument("--dry-run", action="store_true", dest="dry_run")
        parser.add_argument(
            "predicates", nargs="+", help="predicates to match in form 'key=value' "
        )
        parser.set_defaults(func=rm_cmd)

    def _add_run(self, sub):
        parser = sub.add_parser("run", help="Run rules in the specified file")
        parser.add_argument("file", metavar="FILE", help="the input file to parse")
        parser.add_argument(
            "--define", "-D", action="append", type=parse_define, dest="overrides"
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
            "--rulefilter",
            help="If set, will read this as a file of which rules to run",
        )
        parser.add_argument(
            "targets",
            nargs="*",
            help="limit running to these rules and downstream rules",
        )
        parser.set_defaults(func=run_cmd)

    def _add_rules(self, sub):
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
        parser.set_defaults(func=rules_cmd)

    def _add_debugrun(self, sub):
        parser = sub.add_parser(
            "debugrun",
            help="perform query associated with a given rule and report what matched (for debugging why rule doesn't run)",
        )
        parser.add_argument("file", metavar="FILE", help="the input file to parse")
        parser.add_argument("rule", help="the name of the rule to attempt to run")
        parser.add_argument(
            "--save-inputs",
            dest="save_inputs_filename",
            help="If specified write out the inputs dictionary to the given filename",
        )
        parser.set_defaults(func=debugrun_cmd)

    def _add_report(self, sub):
        parser = sub.add_parser(
            "report",
            help="Generate HTML report describing the contents of the state directory",
        )
        parser.add_argument("dest", help="the directory to write the html files to")
        parser.set_defaults(func=report_cmd)

    def _add_export(self, sub):
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
        parser.set_defaults(func=export_cmd)

    def _add_version(self, sub):
        parser = sub.add_parser("version", help="prints version")
        parser.set_defaults(func=version_cmd)

    def _add_history_cmd(self, sub):
        parser = sub.add_parser("history", help="Print the history of all executions")
        parser.set_defaults(func=history_cmd)

    def _add_localize(self, sub):
        parser = sub.add_parser(
            "localize", help="Download any artifacts with $file_url references"
        )
        parser.add_argument("--space")
        parser.add_argument("file", metavar="FILE", help="the input file to parse")
        parser.add_argument(
            "predicates", nargs="+", help="predicates to match in form 'key=value' "
        )
        parser.set_defaults(func=localize_cmd)

    def _add_downstream(self, sub):
        parser = sub.add_parser("downstream", help="List downstream artifacts")
        parser.add_argument(
            "predicates", nargs="*", help="predicates to match in form 'key=value' "
        )
        parser.add_argument("--space")
        parser.set_defaults(func=downstream_cmd)

    def _add_stage(self, sub):
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
        parser.add_argument("output_script", help="path to write test harness to")
        parser.set_defaults(func=stage_cmd)

    def parse_args(self, args=None):
        """Parse command line arguments"""
        return self.parser.parse_args(args)
