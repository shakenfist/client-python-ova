"""The descriptor corpus tier: the parser against every descriptor in two upstream collections.

The collections (govmomi's ovf/fixtures and COT's COT/tests) are fetched at pinned commits by
tools/fetch-descriptor-corpus.sh, which is also the only place the pins are written: this module reads them from
it. Run the tier with "tox -edescriptor-corpus". It lives outside .stestr.conf's test_path so that the offline unit
tier never collects it.

A descriptor is named by a key, "<repo>:<path>", where <repo> is govmomi or cot and <path> is relative to the pinned
subdirectory, using "/". That is the form of the lines in curated.txt.

* ledger.txt records the outcome of every descriptor: "<key>", a tab, and "model" or the parser's outcome_name.
* curated.expected.json holds the full expected parse of each descriptor in curated.txt, as one JSON object keyed by
  key. Prose fields are scrubbed first, so that no vendor text is committed.

OVF_UPDATE_EXPECTED=1 rewrites both from the parser's current behaviour and then fails every test which rewrote
something (see shakenfist_client_ova/tests/golden.py), so a run which updates can never pass.

If a corpus has not been fetched these tests fail, never skip: a missing corpus must not look like a clean run.
"""

import difflib
import json
import os
import re
import subprocess
import sys
import tempfile

import testtools

from shakenfist_client_ova import ovf
from shakenfist_client_ova.tests import golden


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
FETCH_SCRIPT = os.path.join(ROOT, 'tools', 'fetch-descriptor-corpus.sh')
CLASSIFIER = os.path.join(ROOT, 'tools', 'classify-ovf-corpus.py')
CACHE = os.path.join(ROOT, '.cache', 'ovf-corpora')

LEDGER = os.path.join(HERE, 'ledger.txt')
CURATED = os.path.join(HERE, 'curated.txt')
CURATED_OVERRIDES = os.path.join(HERE, 'curated-overrides.txt')
CURATED_EXPECTED = os.path.join(HERE, 'curated.expected.json')

# The corpora in the order the classifier takes them, with the variable prefix each has in the fetch script.
REPOS = ('govmomi', 'cot')


class CorpusUnavailable(Exception):
    pass


def read_pins(script=FETCH_SCRIPT):
    """The pinned (sha, subdirectory) of each corpus, read from the fetch script."""
    with open(script, encoding='utf-8') as f:
        text = f.read()

    pins = {}
    for repo in REPOS:
        values = []
        for suffix in ('SHA', 'PATH'):
            variable = '%s_%s' % (repo.upper(), suffix)
            match = re.search(r'^%s=(\S+)$' % variable, text, re.MULTILINE)
            if not match:
                raise CorpusUnavailable('%s has no line "%s=..." to read the pin from' % (script, variable))
            values.append(match.group(1))
        pins[repo] = tuple(values)
    return pins


def walk_descriptors(directory):
    """Every .ovf file under directory, as a path relative to it using "/"."""
    found = []
    for base, _, names in os.walk(directory):
        for name in names:
            if name.endswith('.ovf'):
                found.append(os.path.relpath(os.path.join(base, name), directory).replace(os.sep, '/'))
    return sorted(found)


def corpus_directories():
    """The pinned subdirectory of each fetched corpus, or raise CorpusUnavailable."""
    directories = {}
    for repo, (sha, subdirectory) in read_pins().items():
        directory = os.path.join(CACHE, '%s-%s' % (repo, sha), *subdirectory.split('/'))
        if not os.path.isdir(directory):
            raise CorpusUnavailable('%s does not exist' % directory)
        if not walk_descriptors(directory):
            raise CorpusUnavailable('%s holds no .ovf file' % directory)
        directories[repo] = directory
    return directories


def read_keys(filename):
    """The keys in curated.txt: one "<repo>:<path>" per line, UTF-8, ending in a newline."""
    with open(filename, 'rb') as f:
        text = f.read().decode('utf-8')
    if text and not text.endswith('\n'):
        raise ValueError('%s does not end with a newline' % filename)
    return text.split('\n')[:-1]


def split_key(key):
    repo, colon, path = key.partition(':')
    if not colon or repo not in REPOS or not path:
        raise ValueError('%r is not a "<repo>:<path>" key for one of %s' % (key, ', '.join(REPOS)))
    return repo, path


class CorpusTestCase(testtools.TestCase):
    """Fails, rather than skips, when a corpus is missing."""

    def setUp(self):
        super().setUp()
        try:
            self.directories = corpus_directories()
        except CorpusUnavailable as e:
            self.fail(
                'The upstream descriptor corpora are not fetched: %s. Run tools/fetch-descriptor-corpus.sh, which '
                '"tox -edescriptor-corpus" does first. These tests fail instead of skipping, so that a missing '
                'corpus cannot pass as a clean run.' % e)

    def path_of(self, key):
        repo, path = split_key(key)
        return os.path.join(self.directories[repo], *path.split('/'))

    def outcome_of(self, key, scrub=False):
        return golden.outcome(self.path_of(key), scrub)

    def fail_if_updating(self, filename):
        if golden.update_mode():
            self.fail('%s=1: rewrote %s. Review git diff, choose any "%s" fragment, and run again without the '
                      'variable.' % (golden.UPDATE_VARIABLE, os.path.relpath(filename, ROOT), golden.PLACEHOLDER))


class DescriptorCorpusTestCase(CorpusTestCase):
    def test_ledger_matches(self):
        outcomes = {}
        for repo, directory in self.directories.items():
            for path in walk_descriptors(directory):
                key = '%s:%s' % (repo, path)
                if '\t' in key or '\n' in key:
                    self.fail('%s cannot be recorded in the ledger, because it holds a tab or a newline' % repr(key))
                model_text, exc = self.outcome_of(key)
                outcomes[key] = 'model' if exc is None else ovf.outcome_name(exc)
        actual = ''.join('%s\t%s\n' % (key, outcomes[key]) for key in sorted(outcomes))

        if golden.update_mode():
            golden.write(LEDGER, actual)
            self.fail_if_updating(LEDGER)

        expected = golden.read(LEDGER)
        if expected is None:
            self.fail('There is no ledger; run with %s=1 to create %s' % (golden.UPDATE_VARIABLE, LEDGER))
        recorded = dict(line.rpartition('\t')[::2] for line in expected.split('\n')[:-1])

        differences = []
        for key in sorted(set(recorded) | set(outcomes)):
            if key not in outcomes:
                differences.append('%s: in the ledger, but not in the cache' % key)
            elif key not in recorded:
                differences.append('%s: %s, but not in the ledger' % (key, outcomes[key]))
            elif recorded[key] != outcomes[key]:
                differences.append('%s: the ledger says %s, the parser gives %s' % (key, recorded[key], outcomes[key]))
        if differences:
            shown = differences[:20]
            if len(differences) > len(shown):
                shown.append('... and %d more' % (len(differences) - len(shown)))
            self.fail('The ledger differs from the parser on %d descriptors:\n%s' % (
                len(differences), '\n'.join(shown)))
        # The same entries, but not in the same form: unsorted, or without a final newline.
        self.assertEqual(expected, actual, 'ledger.txt must be sorted, with one entry per line')

    def test_curated_descriptors_match_their_expected_parse(self):
        keys = read_keys(CURATED)

        if golden.update_mode():
            try:
                old = json.loads(golden.read(CURATED_EXPECTED))
            except (TypeError, ValueError):
                old = {}
            entries = {}
            for key in keys:
                model_text, exc = self.outcome_of(key, scrub=True)
                entries[key] = golden.expected_entry(model_text, exc, old.get(key))
            golden.write(CURATED_EXPECTED, golden.dump(entries))
            self.fail_if_updating(CURATED_EXPECTED)

        text = golden.read(CURATED_EXPECTED)
        if text is None:
            self.fail('There is no %s; run with %s=1 to create it' % (CURATED_EXPECTED, golden.UPDATE_VARIABLE))
        expected = json.loads(text)

        problems = []
        for key in sorted(set(keys) ^ set(expected)):
            problems.append('%s: %s' % (key, 'in curated.txt but has no expected value' if key in keys
                                        else 'has an expected value but is not in curated.txt'))
        for key in keys:
            if key in expected:
                model_text, exc = self.outcome_of(key, scrub=True)
                message = golden.problem(key, expected[key], model_text, exc)
                if message:
                    problems.append(message)
        if problems:
            self.fail('%d of %d curated descriptors differ from curated.expected.json:\n%s' % (
                len(problems), len(keys), '\n'.join(problems)))
        self.assertEqual(text, golden.dump(expected), 'curated.expected.json is not in the canonical form')

    def test_curated_descriptors_exist(self):
        missing = [key for key in read_keys(CURATED) if not os.path.isfile(self.path_of(key))]
        self.assertEqual([], missing, 'curated.txt names descriptors which are not in the pinned corpora')

    def test_classifier_reproduces_the_curated_list(self):
        # The arguments are the ones in the classifier's docstring, with the directories the fetch script pins.
        # The output goes to a temporary file, not curated.txt, which this test must not rewrite.
        with tempfile.TemporaryDirectory() as scratch:
            output = os.path.join(scratch, 'curated.txt')
            command = [
                sys.executable, '-I', CLASSIFIER, '--curate', '2', '--overrides', CURATED_OVERRIDES,
                '--output', output,
                'govmomi=%s' % self.directories['govmomi'], 'cot=%s:1' % self.directories['cot']]
            result = subprocess.run(command, cwd=scratch, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(
                0, result.returncode, 'The classifier failed: %s' % result.stderr.decode('utf-8', 'replace'))
            with open(output, 'rb') as f:
                produced = f.read()
        with open(CURATED, 'rb') as f:
            committed = f.read()
        if committed != produced:
            diff = list(difflib.unified_diff(
                committed.decode('utf-8').splitlines(), produced.decode('utf-8').splitlines(), 'curated.txt',
                'the classifier', lineterm='', n=0))
            self.fail('tools/classify-ovf-corpus.py no longer produces curated.txt; regenerate it, as its docstring '
                      'says:\n%s' % '\n'.join(diff[:30]))
