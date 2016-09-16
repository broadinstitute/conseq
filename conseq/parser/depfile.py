#!/usr/bin/env python
# -*- coding: utf-8 -*-

# CAVEAT UTILITOR
#
# This file was automatically generated by Grako.
#
#    https://pypi.python.org/pypi/grako/
#
# Any changes you make to it will be overwritten the next time
# the file is generated.


from __future__ import print_function, division, absolute_import, unicode_literals

from grako.parsing import graken, Parser
from grako.util import re, RE_FLAGS, generic_main  # noqa


__version__ = (2016, 9, 15, 20, 27, 16, 3)

__all__ = [
    'depfileParser',
    'depfileSemantics',
    'main'
]

KEYWORDS = set([])


class depfileParser(Parser):
    def __init__(self,
                 whitespace=None,
                 nameguard=None,
                 comments_re=None,
                 eol_comments_re='#.*?$',
                 ignorecase=None,
                 left_recursion=True,
                 keywords=KEYWORDS,
                 **kwargs):
        super(depfileParser, self).__init__(
            whitespace=whitespace,
            nameguard=nameguard,
            comments_re=comments_re,
            eol_comments_re=eol_comments_re,
            ignorecase=ignorecase,
            left_recursion=left_recursion,
            keywords=keywords,
            **kwargs
        )

    @graken()
    def _triple_dbl_quoted_string_(self):
        self._pattern(r'"""(?:[^"]|"{1,2}(?!"))+"""')

    @graken()
    def _dbl_quoted_string_(self):
        self._pattern(r'"[^"]*"')

    @graken()
    def _triple_squoted_string_(self):
        self._pattern(r"'''(?:[^']|'{1,2}(?!'))+'''")

    @graken()
    def _squoted_string_(self):
        self._pattern(r"'[^']*'")

    @graken()
    def _quoted_string_(self):
        with self._choice():
            with self._option():
                self._triple_dbl_quoted_string_()
            with self._option():
                self._dbl_quoted_string_()
            with self._option():
                self._squoted_string_()
            with self._option():
                self._triple_squoted_string_()
            self._error('no available options')

    @graken()
    def _identifier_(self):
        self._pattern(r'[A-Za-z]+[A-Za-z0-9_+-]*')

    @graken()
    def _url_(self):
        self._pattern(r'\S+')

    @graken()
    def _json_value_(self):
        with self._choice():
            with self._option():
                self._quoted_string_()
            with self._option():
                self._json_obj_()
            self._error('no available options')

    @graken()
    def _json_name_value_pair_(self):
        self._quoted_string_()
        self._token(':')
        self._json_value_()

    @graken()
    def _json_obj_(self):
        self._token('{')
        self._json_name_value_pair_()

        def block0():
            self._token(',')
            self._json_name_value_pair_()
        self._closure(block0)
        self._token('}')

    @graken()
    def _query_variable_(self):
        self._identifier_()

    @graken()
    def _query_name_value_pair_(self):
        with self._choice():
            with self._option():
                self._quoted_string_()
                self._token(':')
                with self._group():
                    with self._choice():
                        with self._option():
                            self._json_value_()
                        with self._option():
                            self._query_variable_()
                        self._error('no available options')
            with self._option():
                self._quoted_string_()
                self._token('~')
                self._quoted_string_()
            self._error('no available options')

    @graken()
    def _query_obj_(self):
        self._token('{')
        self._query_name_value_pair_()

        def block0():
            self._token(',')
            self._query_name_value_pair_()
        self._closure(block0)
        self._token('}')

    @graken()
    def _input_spec_each_(self):
        self._identifier_()
        self._token('=')
        self._query_obj_()

    @graken()
    def _input_spec_all_(self):
        self._identifier_()
        self._token('=')
        self._token('all')
        self._query_obj_()

    @graken()
    def _input_spec_(self):
        with self._choice():
            with self._option():
                self._input_spec_each_()
            with self._option():
                self._input_spec_all_()
            self._error('no available options')

    @graken()
    def _input_specs_(self):
        self._input_spec_()

        def block0():
            self._token(',')
            self._input_spec_()
        self._closure(block0)

    @graken()
    def _output_specs_(self):
        self._json_obj_()

        def block0():
            self._token(',')
            self._json_obj_()
        self._closure(block0)

    @graken()
    def _type_def_(self):
        self._token('type')
        self._identifier_()
        self._token('has')
        self._token('{')
        self._identifier_()

        def block0():
            self._token(',')
            self._identifier_()
        self._closure(block0)
        self._token('}')

    @graken()
    def _expected_output_type_(self):
        self._identifier_()

        def block0():
            with self._choice():
                with self._option():
                    self._token('?')
                with self._option():
                    self._token('+')
                with self._option():
                    self._empty_closure()
                self._error('expecting one of: + ?')
        self._closure(block0)

    @graken()
    def _expected_output_types_(self):
        self._expected_output_type_()

        def block0():
            self._token(',')
            self._expected_output_type_()
        self._closure(block0)

    @graken()
    def _run_statement_(self):
        self._token('run')
        self._quoted_string_()
        with self._optional():
            self._token('with')
            self._quoted_string_()

    @graken()
    def _requirement_def_(self):
        self._identifier_()
        self._token('=')
        self._pattern(r'[0-9]+')

    @graken()
    def _rule_parameters_(self):
        with self._group():
            with self._choice():
                with self._option():
                    self._token('inputs')
                    self._token(':')
                    self._input_specs_()
                with self._option():
                    self._token('outputs')
                    self._token(':')
                    self._output_specs_()
                with self._option():
                    self._token('expect-outputs')
                    self._token(':')
                    self._expected_output_types_()
                with self._option():
                    self._token('options')
                    self._token(':')
                    self._identifier_()

                    def block0():
                        self._token(',')
                        self._identifier_()
                    self._closure(block0)
                with self._option():
                    self._token('executor')
                    self._token(':')
                    self._identifier_()
                with self._option():
                    self._token('resources')
                    self._token(':')
                    self._json_obj_()
                with self._option():
                    self._token('requires')
                    self._token(':')
                    self._requirement_def_()

                    def block1():
                        self._token(',')
                        self._requirement_def_()
                    self._closure(block1)
                self._error('no available options')

    @graken()
    def _rule_(self):
        self._token('rule')
        self._identifier_()
        self._token(':')

        def block0():
            self._rule_parameters_()
        self._closure(block0)

        def block1():
            self._run_statement_()
        self._closure(block1)

    @graken()
    def _xref_(self):
        self._token('xref')
        self._url_()
        self._json_obj_()

    @graken()
    def _add_if_missing_(self):
        self._token('add-if-missing')
        self._json_obj_()

    @graken()
    def _exec_profile_(self):
        self._token('exec-profile')
        self._identifier_()
        self._json_obj_()

    @graken()
    def _var_stmt_(self):
        self._token('let')
        self._identifier_()
        self._token('=')
        self._quoted_string_()

    @graken()
    def _include_stmt_(self):
        self._token('include')
        self._quoted_string_()

    @graken()
    def _declarations_(self):

        def block0():
            with self._choice():
                with self._option():
                    self._rule_()
                with self._option():
                    self._xref_()
                with self._option():
                    self._include_stmt_()
                with self._option():
                    self._var_stmt_()
                with self._option():
                    self._add_if_missing_()
                with self._option():
                    self._type_def_()
                with self._option():
                    self._exec_profile_()
                self._error('no available options')
        self._positive_closure(block0)
        self._check_eof()


class depfileSemantics(object):
    def triple_dbl_quoted_string(self, ast):
        return ast

    def dbl_quoted_string(self, ast):
        return ast

    def triple_squoted_string(self, ast):
        return ast

    def squoted_string(self, ast):
        return ast

    def quoted_string(self, ast):
        return ast

    def identifier(self, ast):
        return ast

    def url(self, ast):
        return ast

    def json_value(self, ast):
        return ast

    def json_name_value_pair(self, ast):
        return ast

    def json_obj(self, ast):
        return ast

    def query_variable(self, ast):
        return ast

    def query_name_value_pair(self, ast):
        return ast

    def query_obj(self, ast):
        return ast

    def input_spec_each(self, ast):
        return ast

    def input_spec_all(self, ast):
        return ast

    def input_spec(self, ast):
        return ast

    def input_specs(self, ast):
        return ast

    def output_specs(self, ast):
        return ast

    def type_def(self, ast):
        return ast

    def expected_output_type(self, ast):
        return ast

    def expected_output_types(self, ast):
        return ast

    def run_statement(self, ast):
        return ast

    def requirement_def(self, ast):
        return ast

    def rule_parameters(self, ast):
        return ast

    def rule(self, ast):
        return ast

    def xref(self, ast):
        return ast

    def add_if_missing(self, ast):
        return ast

    def exec_profile(self, ast):
        return ast

    def var_stmt(self, ast):
        return ast

    def include_stmt(self, ast):
        return ast

    def declarations(self, ast):
        return ast


def main(
        filename,
        startrule,
        trace=False,
        whitespace=None,
        nameguard=None,
        comments_re=None,
        eol_comments_re='#.*?$',
        ignorecase=None,
        left_recursion=True,
        **kwargs):

    with open(filename) as f:
        text = f.read()
    parser = depfileParser(parseinfo=False)
    ast = parser.parse(
        text,
        startrule,
        filename=filename,
        trace=trace,
        whitespace=whitespace,
        nameguard=nameguard,
        ignorecase=ignorecase,
        **kwargs)
    return ast

if __name__ == '__main__':
    import json
    ast = generic_main(main, depfileParser, name='depfile')
    print('AST:')
    print(ast)
    print()
    print('JSON:')
    print(json.dumps(ast, indent=2))
    print()
