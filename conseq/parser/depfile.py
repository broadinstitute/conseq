#!/usr/bin/env python
# -*- coding: utf-8 -*-

# CAVEAT UTILITOR
#
# This file was automatically generated by TatSu.
#
#    https://pypi.python.org/pypi/tatsu/
#
# Any changes you make to it will be overwritten the next time
# the file is generated.


from __future__ import print_function, division, absolute_import, unicode_literals

import sys

from tatsu.buffering import Buffer
from tatsu.parsing import Parser
from tatsu.parsing import tatsumasu, leftrec, nomemo
from tatsu.parsing import leftrec, nomemo  # noqa
from tatsu.util import re, generic_main  # noqa


KEYWORDS = {}  # type: ignore


class depfileBuffer(Buffer):
    def __init__(
        self,
        text,
        whitespace=None,
        nameguard=None,
        comments_re=None,
        eol_comments_re='#.*?$',
        ignorecase=None,
        namechars='',
        **kwargs
    ):
        super(depfileBuffer, self).__init__(
            text,
            whitespace=whitespace,
            nameguard=nameguard,
            comments_re=comments_re,
            eol_comments_re=eol_comments_re,
            ignorecase=ignorecase,
            namechars=namechars,
            **kwargs
        )


class depfileParser(Parser):
    def __init__(
        self,
        whitespace=None,
        nameguard=None,
        comments_re=None,
        eol_comments_re='#.*?$',
        ignorecase=None,
        left_recursion=True,
        parseinfo=True,
        keywords=None,
        namechars='',
        buffer_class=depfileBuffer,
        **kwargs
    ):
        if keywords is None:
            keywords = KEYWORDS
        super(depfileParser, self).__init__(
            whitespace=whitespace,
            nameguard=nameguard,
            comments_re=comments_re,
            eol_comments_re=eol_comments_re,
            ignorecase=ignorecase,
            left_recursion=left_recursion,
            parseinfo=parseinfo,
            keywords=keywords,
            namechars=namechars,
            buffer_class=buffer_class,
            **kwargs
        )

    @tatsumasu()
    def _triple_dbl_quoted_string_(self):  # noqa
        self._pattern('"""(?:[^"]|"{1,2}(?!"))+"""')

    @tatsumasu()
    def _dbl_quoted_string_(self):  # noqa
        self._pattern('"[^"]*"')

    @tatsumasu()
    def _triple_squoted_string_(self):  # noqa
        self._pattern("'''(?:[^']|'{1,2}(?!'))+'''")

    @tatsumasu()
    def _squoted_string_(self):  # noqa
        self._pattern("'[^']*'")

    @tatsumasu()
    def _quoted_string_(self):  # noqa
        with self._choice():
            with self._option():
                self._triple_dbl_quoted_string_()
            with self._option():
                self._dbl_quoted_string_()
            with self._option():
                self._triple_squoted_string_()
            with self._option():
                self._squoted_string_()
            self._error('no available options')

    @tatsumasu()
    def _identifier_(self):  # noqa
        self._pattern('[A-Za-z]+[A-Za-z0-9_+-]*')

    @tatsumasu()
    def _json_value_(self):  # noqa
        with self._choice():
            with self._option():
                self._quoted_string_()
            with self._option():
                self._json_obj_()
            with self._option():
                self._json_array_()
            self._error('no available options')

    @tatsumasu()
    def _json_array_(self):  # noqa
        with self._choice():
            with self._option():
                self._token('[')
                self._json_value_()
                self.name_last_node('first')

                def block2():
                    self._token(',')
                    self._json_value_()
                    self.name_last_node('value')
                self._closure(block2)
                self.name_last_node('rest')
                self._token(']')
            with self._option():
                self._token('[')
                self._token(']')
            self._error('no available options')
        self.ast._define(
            ['first', 'rest', 'value'],
            []
        )

    @tatsumasu()
    def _json_name_value_pair_(self):  # noqa
        self._quoted_string_()
        self.name_last_node('name')
        self._token(':')
        self._json_value_()
        self.name_last_node('value')
        self.ast._define(
            ['name', 'value'],
            []
        )

    @tatsumasu()
    def _json_obj_(self):  # noqa
        self._token('{')
        self._json_name_value_pair_()
        self.name_last_node('first')

        def block2():
            self._token(',')
            self._json_name_value_pair_()
        self._closure(block2)
        self.name_last_node('rest')
        with self._optional():
            self._token(',')
        self._token('}')
        self.ast._define(
            ['first', 'rest'],
            []
        )

    @tatsumasu()
    def _query_variable_(self):  # noqa
        self._identifier_()

    @tatsumasu()
    def _query_name_value_pair_(self):  # noqa
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

    @tatsumasu()
    def _pattern_based_query_obj_(self):  # noqa
        self._token('{')
        self._query_name_value_pair_()

        def block0():
            self._token(',')
            self._query_name_value_pair_()
        self._closure(block0)
        self._token('}')

    @tatsumasu()
    def _fileref_option_(self):  # noqa
        self._token('copy_to')

    @tatsumasu()
    def _fileref_query_obj_(self):  # noqa
        with self._group():
            with self._choice():
                with self._option():
                    self._token('fileref')
                with self._option():
                    self._token('filename')
                self._error('no available options')
        self._token('(')
        self._quoted_string_()
        self.name_last_node('filename')

        def block3():
            self._token(',')
            self._fileref_option_()
            self._token('=')
            self._quoted_string_()
        self._closure(block3)
        self.name_last_node('options')
        self._token(')')
        self.ast._define(
            ['filename', 'options'],
            []
        )

    @tatsumasu()
    def _query_obj_(self):  # noqa
        with self._choice():
            with self._option():
                self._pattern_based_query_obj_()
            with self._option():
                self._fileref_query_obj_()
            self._error('no available options')

    @tatsumasu()
    def _input_spec_each_(self):  # noqa
        self._identifier_()
        self._token('=')
        self._query_obj_()

    @tatsumasu()
    def _input_spec_all_(self):  # noqa
        self._identifier_()
        self._token('=')
        self._token('all')
        self._query_obj_()

    @tatsumasu()
    def _input_spec_(self):  # noqa
        with self._choice():
            with self._option():
                self._input_spec_each_()
            with self._option():
                self._input_spec_all_()
            self._error('no available options')

    @tatsumasu()
    def _input_specs_(self):  # noqa
        self._input_spec_()

        def block0():
            self._token(',')
            self._input_spec_()
        self._closure(block0)
        with self._optional():
            self._token(',')

    @tatsumasu()
    def _output_specs_(self):  # noqa
        with self._choice():
            with self._option():
                self._json_obj_()

                def block0():
                    self._token(',')
                    self._json_obj_()
                self._closure(block0)
                with self._optional():
                    self._token(',')
            with self._option():
                self._token('none')
            self._error('no available options')

    @tatsumasu()
    def _construct_cache_key_run_(self):  # noqa
        self._token('construct-cache-key-run')
        self._quoted_string_()
        with self._optional():
            self._token('with')
            self._quoted_string_()

    @tatsumasu()
    def _run_statement_(self):  # noqa
        self._token('run')
        self._quoted_string_()
        with self._optional():
            self._token('with')
            self._quoted_string_()

    @tatsumasu()
    def _file_list_(self):  # noqa
        self._quoted_string_()

        def block0():
            self._token(',')
            self._quoted_string_()
        self._closure(block0)

    @tatsumasu()
    def _rule_parameters_(self):  # noqa
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
                    self._token('outputs-expected')
                    self._token(':')
                    with self._group():
                        self._identifier_()

                        def block0():
                            self._token(',')
                            self._identifier_()
                        self._closure(block0)
                with self._option():
                    self._token('executor')
                    self._token(':')
                    self._identifier_()
                    self._json_obj_()
                with self._option():
                    self._token('executor')
                    self._token(':')
                    self._identifier_()
                with self._option():
                    self._token('watch-regex')
                    self._token(':')
                    self._quoted_string_()
                with self._option():
                    self._token('publish')
                    self._token(':')
                    self._quoted_string_()
                with self._option():
                    self._token('resources')
                    self._token(':')
                    self._json_obj_()
                with self._option():
                    self._token('uses')
                    self._token(':')
                    self._file_list_()
                self._error('no available options')

    @tatsumasu()
    def _rule_(self):  # noqa
        self._token('rule')
        self._identifier_()
        self.name_last_node('name')
        self._token(':')

        def block2():
            self._rule_parameters_()
        self._closure(block2)
        self.name_last_node('params')

        def block4():
            self._construct_cache_key_run_()
        self._closure(block4)
        self.name_last_node('cachekeystmts')

        def block6():
            self._run_statement_()
        self._closure(block6)
        self.name_last_node('stmts')
        self.ast._define(
            ['cachekeystmts', 'name', 'params', 'stmts'],
            []
        )

    @tatsumasu()
    def _add_if_missing_(self):  # noqa

        def block0():
            with self._choice():
                with self._option():
                    self._token('add-if-missing')
                with self._option():
                    self._token('add-artifact')
                self._error('no available options')
        self._closure(block0)
        self._json_obj_()

    @tatsumasu()
    def _remember_executed_input_(self):  # noqa
        self._token('input')
        self._quoted_string_()
        self._token(':')

        def block0():
            with self._choice():
                with self._option():
                    self._json_obj_()
                with self._option():
                    self._json_array_()
                self._error('no available options')
        self._closure(block0)

    @tatsumasu()
    def _remember_executed_output_(self):  # noqa
        self._token('output')
        self._token(':')
        self._json_obj_()

    @tatsumasu()
    def _remember_executed_(self):  # noqa
        self._token('remember-executed')
        self._token('transform')
        self._token(':')
        self._quoted_string_()

        def block0():
            self._remember_executed_input_()
        self._closure(block0)

        def block1():
            self._remember_executed_output_()
        self._closure(block1)

    @tatsumasu()
    def _exec_profile_(self):  # noqa
        self._token('executor-template')
        self._identifier_()
        self._json_obj_()

    @tatsumasu()
    def _var_stmt_(self):  # noqa
        self._token('let')
        self._identifier_()
        self._token('=')
        self._quoted_string_()

    @tatsumasu()
    def _include_stmt_(self):  # noqa
        self._token('include')
        self._quoted_string_()

    @tatsumasu()
    def _conditional_expr_(self):  # noqa
        self._quoted_string_()

    @tatsumasu()
    def _eval_statement_(self):  # noqa
        self._token('eval')
        self._quoted_string_()

    @tatsumasu()
    def _conditional_(self):  # noqa
        self._token('if')
        self._conditional_expr_()
        self.name_last_node('condition')
        self._token(':')
        self._declarations_()
        self.name_last_node('true_body')

        def block3():
            self._token('elif')
            self._conditional_expr_()
            self._token(':')
            self._declarations_()
        self._closure(block3)
        self.name_last_node('elif_clauses')
        with self._optional():
            self._token('else')
            self._token(':')
            self._declarations_()
        self.name_last_node('else_clause')
        self._token('endif')
        self.ast._define(
            ['condition', 'elif_clauses', 'else_clause', 'true_body'],
            []
        )

    @tatsumasu()
    def _type_definition_field_(self):  # noqa
        with self._group():
            with self._choice():
                with self._option():
                    self._token('description')
                    self._token(':')
                    self._quoted_string_()
                with self._option():
                    self._token('required')
                    self._token(':')
                    self._json_array_()
                self._error('no available options')

    @tatsumasu()
    def _type_definition_(self):  # noqa
        self._token('{')
        self._type_definition_field_()

        def block0():
            self._token(',')
            self._type_definition_field_()
        self._closure(block0)
        self._token('}')

    @tatsumasu()
    def _type_def_stmt_(self):  # noqa
        self._token('type')
        self._identifier_()
        self._token('=')
        self._type_definition_()

    @tatsumasu()
    def _declarations_(self):  # noqa

        def block0():
            with self._choice():
                with self._option():
                    self._rule_()
                with self._option():
                    self._include_stmt_()
                with self._option():
                    self._var_stmt_()
                with self._option():
                    self._add_if_missing_()
                with self._option():
                    self._exec_profile_()
                with self._option():
                    self._remember_executed_()
                with self._option():
                    self._conditional_()
                with self._option():
                    self._eval_statement_()
                with self._option():
                    self._type_def_stmt_()
                self._error('no available options')
        self._positive_closure(block0)

    @tatsumasu()
    def _all_declarations_(self):  # noqa
        with self._optional():
            self._declarations_()
        self._check_eof()


class depfileSemantics(object):
    def triple_dbl_quoted_string(self, ast):  # noqa
        return ast

    def dbl_quoted_string(self, ast):  # noqa
        return ast

    def triple_squoted_string(self, ast):  # noqa
        return ast

    def squoted_string(self, ast):  # noqa
        return ast

    def quoted_string(self, ast):  # noqa
        return ast

    def identifier(self, ast):  # noqa
        return ast

    def json_value(self, ast):  # noqa
        return ast

    def json_array(self, ast):  # noqa
        return ast

    def json_name_value_pair(self, ast):  # noqa
        return ast

    def json_obj(self, ast):  # noqa
        return ast

    def query_variable(self, ast):  # noqa
        return ast

    def query_name_value_pair(self, ast):  # noqa
        return ast

    def pattern_based_query_obj(self, ast):  # noqa
        return ast

    def fileref_option(self, ast):  # noqa
        return ast

    def fileref_query_obj(self, ast):  # noqa
        return ast

    def query_obj(self, ast):  # noqa
        return ast

    def input_spec_each(self, ast):  # noqa
        return ast

    def input_spec_all(self, ast):  # noqa
        return ast

    def input_spec(self, ast):  # noqa
        return ast

    def input_specs(self, ast):  # noqa
        return ast

    def output_specs(self, ast):  # noqa
        return ast

    def construct_cache_key_run(self, ast):  # noqa
        return ast

    def run_statement(self, ast):  # noqa
        return ast

    def file_list(self, ast):  # noqa
        return ast

    def rule_parameters(self, ast):  # noqa
        return ast

    def rule(self, ast):  # noqa
        return ast

    def add_if_missing(self, ast):  # noqa
        return ast

    def remember_executed_input(self, ast):  # noqa
        return ast

    def remember_executed_output(self, ast):  # noqa
        return ast

    def remember_executed(self, ast):  # noqa
        return ast

    def exec_profile(self, ast):  # noqa
        return ast

    def var_stmt(self, ast):  # noqa
        return ast

    def include_stmt(self, ast):  # noqa
        return ast

    def conditional_expr(self, ast):  # noqa
        return ast

    def eval_statement(self, ast):  # noqa
        return ast

    def conditional(self, ast):  # noqa
        return ast

    def type_definition_field(self, ast):  # noqa
        return ast

    def type_definition(self, ast):  # noqa
        return ast

    def type_def_stmt(self, ast):  # noqa
        return ast

    def declarations(self, ast):  # noqa
        return ast

    def all_declarations(self, ast):  # noqa
        return ast


def main(filename, start=None, **kwargs):
    if start is None:
        start = 'triple_dbl_quoted_string'
    if not filename or filename == '-':
        text = sys.stdin.read()
    else:
        with open(filename) as f:
            text = f.read()
    parser = depfileParser()
    return parser.parse(text, rule_name=start, filename=filename, **kwargs)


if __name__ == '__main__':
    import json
    from tatsu.util import asjson

    ast = generic_main(main, depfileParser, name='depfile')
    print('AST:')
    print(ast)
    print()
    print('JSON:')
    print(json.dumps(asjson(ast), indent=2))
    print()
