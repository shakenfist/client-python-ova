"""The import boundary around shakenfist_client_ova/ovf/.

The parser is built to be spun out of this repository, so it may import only
the standard library and its own parsing dependencies, never the command's
(click, shakenfist_client), and it never prints or exits: it raises OVFError
and the command does the talking. This reads the source of every module in
ovf/ rather than importing it, so a violation fails here however it is reached.
"""

import ast
import os

import testtools


OVF_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'ovf')

# Every top-level module ovf/ may import. A standard library module is added
# here when the parser starts to use it, so that each new dependency is a
# reviewed change to this list.
ALLOWED_IMPORTS = frozenset([
    # The standard library modules ovf/ uses.
    'dataclasses',
    'json',
    'math',
    're',
    'typing',

    # Third-party parsing dependencies.
    'defusedxml',
    # Allowed only until the parser moves to ElementTree through defusedxml
    # (see docs/plans/PLAN-ovf-parser.md), when both leave this list.
    'dpath',
    'xmltodict',
])

# The only parts of the standard library's xml package ovf/ may import, by full dotted name: xml.parsers.expat for
# ExpatError (and xml.parsers, which holds only expat, for "from xml.parsers import expat"). Every other xml module is
# a stdlib parser which bypasses defusedxml's protections, so the package is not allowed as a whole.
ALLOWED_XML_MODULES = frozenset(['xml.parsers', 'xml.parsers.expat'])

# The command's dependencies, refused by a rule of their own so that the
# failure says what broke rather than that something is not on a list.
FORBIDDEN_IMPORTS = frozenset(['click', 'shakenfist_client'])

# Calls that print or exit, as names, and as (module, attribute) pairs.
FORBIDDEN_CALLS = frozenset(['print', 'exit', 'quit'])
FORBIDDEN_ATTRIBUTE_CALLS = frozenset([('sys', 'exit'), ('os', '_exit')])


def _imports(tree):
    """Each absolute import in tree, as (line number, dotted module name)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield node.lineno, alias.name
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            yield node.lineno, node.module


def _top_level(module):
    return module.split('.')[0]


def forbidden_imports(tree):
    return ['line %d: imports %s' % (lineno, module) for lineno, module in _imports(tree)
            if _top_level(module) in FORBIDDEN_IMPORTS]


def unlisted_imports(tree):
    problems = []
    for lineno, module in _imports(tree):
        if _top_level(module) == 'xml':
            if module not in ALLOWED_XML_MODULES:
                problems.append('line %d: imports %s; XML parsing must come through defusedxml, and only '
                                'xml.parsers.expat is allowed from the xml package' % (lineno, module))
        elif _top_level(module) not in ALLOWED_IMPORTS and _top_level(module) not in FORBIDDEN_IMPORTS:
            problems.append('line %d: imports %s, which is not on the allow-list' % (lineno, module))
    return problems


def print_or_exit_calls(tree):
    problems = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in FORBIDDEN_CALLS:
                problems.append('line %d: calls %s()' % (node.lineno, func.id))
            elif (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                    and (func.value.id, func.attr) in FORBIDDEN_ATTRIBUTE_CALLS):
                problems.append('line %d: calls %s.%s()' % (node.lineno, func.value.id, func.attr))
        elif isinstance(node, ast.Raise) and node.exc is not None:
            exc = node.exc.func if isinstance(node.exc, ast.Call) else node.exc
            if isinstance(exc, ast.Name) and exc.id == 'SystemExit':
                problems.append('line %d: raises SystemExit' % node.lineno)
    return problems


def _modules():
    modules = []
    for directory, _, names in os.walk(OVF_DIR):
        for name in sorted(names):
            if name.endswith('.py'):
                modules.append(os.path.join(directory, name))
    return sorted(modules)


def _parse(path):
    with open(path, 'rb') as f:
        return ast.parse(f.read(), filename=path)


class BoundaryTestCase(testtools.TestCase):
    def _check(self, rule, checker):
        problems = []
        for path in _modules():
            name = os.path.relpath(path, os.path.join(OVF_DIR, '..'))
            problems.extend('%s %s' % (name, problem) for problem in checker(_parse(path)))
        if problems:
            self.fail('ovf/ breaks the rule "%s":\n    %s' % (rule, '\n    '.join(problems)))

    def test_modules_found(self):
        names = [os.path.basename(path) for path in _modules()]
        for expected in ('__init__.py', 'descriptor.py', 'errors.py', 'manifest.py', 'model.py', 'prose.py'):
            self.assertIn(expected, names)

    def test_never_imports_the_command_dependencies(self):
        self._check('never import click or shakenfist_client', forbidden_imports)

    def test_imports_only_the_allow_list(self):
        self._check('import only the standard library modules on the allow-list, defusedxml, xmltodict and dpath',
                    unlisted_imports)

    def test_never_prints_or_exits(self):
        self._check('never print or exit; raise an OVFError instead', print_or_exit_calls)


class CheckerTestCase(testtools.TestCase):
    """The checkers themselves, on source written to break each rule."""

    def _tree(self, source):
        return ast.parse(source)

    def test_forbidden_imports(self):
        for source in ('import click', 'from click import echo', 'import shakenfist_client.apiclient',
                       'from shakenfist_client import util'):
            self.assertEqual(1, len(forbidden_imports(self._tree(source))), source)
            self.assertEqual([], unlisted_imports(self._tree(source)), source)

    def test_parent_package_is_not_the_client(self):
        # shakenfist_client_ova starts with shakenfist_client, but is not it;
        # importing it from ovf/ is still refused, by the allow-list.
        tree = self._tree('import shakenfist_client_ova')
        self.assertEqual([], forbidden_imports(tree))
        self.assertEqual(1, len(unlisted_imports(tree)))

    def test_unlisted_imports(self):
        for source in ('import sys', 'import os.path', 'from subprocess import run', 'import humanize'):
            self.assertEqual(1, len(unlisted_imports(self._tree(source))), source)

    def test_allowed_imports(self):
        tree = self._tree('\n'.join([
            'import json', 'from typing import List', 'import csv', 'from defusedxml import ElementTree',
            'import dpath.exceptions', 'from . import errors', 'from .model import Envelope',
            'from xml.parsers.expat import ExpatError', 'import xml.parsers.expat',
            'from xml.parsers import expat']))
        # csv is the standard library, but not used, so not listed.
        self.assertEqual(['line 3: imports csv, which is not on the allow-list'], unlisted_imports(tree))
        self.assertEqual([], forbidden_imports(tree))

    def test_other_xml_parsers_are_refused(self):
        for source in ('import xml.etree.ElementTree', 'from xml.dom import minidom', 'import xml.sax', 'import xml',
                       'from xml import etree'):
            problems = unlisted_imports(self._tree(source))
            self.assertEqual(1, len(problems), source)
            self.assertIn('must come through defusedxml', problems[0], source)

    def test_print_or_exit(self):
        for source in ('print("x")', 'def f():\n    exit(1)', 'quit()', 'sys.exit(1)', 'os._exit(1)',
                       'raise SystemExit(1)', 'raise SystemExit'):
            self.assertEqual(1, len(print_or_exit_calls(self._tree(source))), source)

    def test_other_calls(self):
        tree = self._tree('logging.exit()\nf.print()\nraise ValueError("x")\nsys.exc_info()')
        self.assertEqual([], print_or_exit_calls(tree))
