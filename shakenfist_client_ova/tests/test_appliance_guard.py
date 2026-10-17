"""The appliance corpus tier fails, rather than skips, when its corpus is missing or incomplete.

A skipped corpus test looks like a clean run, so the tier's guard must fail. This runs offline: APPLIANCE_CORPUS is
pointed at a temporary directory of small invented files, so no real appliance is read.
"""

import os
import tempfile
from unittest import mock

import testtools

# The module is imported, not its test cases, so that the loader does not collect them from here.
from shakenfist_client_ova.appliance_tests import test_appliance_corpus as corpus


POINTER = b'version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize 1024\n' % (b'0' * 64)


class ApplianceGuardTestCase(testtools.TestCase):
    def _corpus(self, names=('a', 'b'), ova=b'not a pointer', provenance=None):
        """A directory holding <name>.ova and <name>.provenance.json for each name, which APPLIANCE_CORPUS names."""
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        for name in names:
            with open(os.path.join(scratch.name, name + corpus.OVA_SUFFIX), 'wb') as f:
                f.write(ova)
            if provenance is None or name in provenance:
                with open(os.path.join(scratch.name, name + corpus.PROVENANCE_SUFFIX), 'w') as f:
                    f.write('{"kind": "whole"}\n')
        self._set(scratch.name)
        return scratch.name

    def _set(self, value):
        environment = {} if value is None else {corpus.CORPUS_VARIABLE: value}
        patcher = mock.patch.dict(os.environ, environment)
        patcher.start()
        self.addCleanup(patcher.stop)
        if value is None:
            os.environ.pop(corpus.CORPUS_VARIABLE, None)

    def _assert_unavailable(self, fragment):
        e = self.assertRaises(corpus.CorpusUnavailable, corpus.appliances)
        self.assertIn(fragment, str(e))
        self._assert_fails('missing or incomplete')

    def _assert_fails(self, fragment):
        result = testtools.TestResult()
        corpus.ApplianceCorpusTestCase('test_corpus_is_complete').run(result)
        self.assertEqual(1, result.testsRun)
        self.assertEqual(1, len(result.failures), 'expected a failure; got %r' % (result.__dict__,))
        self.assertEqual({}, result.skip_reasons)
        self.assertEqual([], result.errors)
        self.assertIn(fragment, result.failures[0][1])

    def test_unset_variable(self):
        self._set(None)
        self._assert_unavailable('is not set')

    def test_empty_variable(self):
        self._set('')
        self._assert_unavailable('is not set')

    def test_variable_naming_no_directory(self):
        self._set(os.path.join(self._corpus(), 'nothing-here'))
        self._assert_unavailable('not a directory')

    def test_directory_without_ovas(self):
        self._corpus(names=())
        self._assert_unavailable('holds no .ova file')

    def test_lfs_pointer(self):
        self._corpus(ova=POINTER)
        self._assert_unavailable('Git LFS pointers, not archives: a, b;')

    def test_ova_without_provenance(self):
        self._corpus(provenance=('a',))
        self._assert_unavailable('have no .provenance.json file: b')

    def test_provenance_without_ova(self):
        directory = self._corpus()
        with open(os.path.join(directory, 'c' + corpus.PROVENANCE_SUFFIX), 'w') as f:
            f.write('{}\n')
        self._assert_unavailable('files have no OVA: c')

    def test_appliances_with_one_test_name(self):
        self._corpus(names=('a-b', 'a.b'))
        self._assert_unavailable('would have the same test name')

    def test_complete_corpus(self):
        directory = self._corpus()
        self.assertEqual((directory, ['a', 'b']), corpus.appliances())

    def test_stale_expected_entry_fails(self):
        self._corpus()
        self._assert_fails('expected.json names appliances which are not in the corpus')

    def test_corpus_holding_every_expected_appliance_is_complete(self):
        self._corpus(names=sorted(corpus.read_expected()))
        result = testtools.TestResult()
        corpus.ApplianceCorpusTestCase('test_corpus_is_complete').run(result)
        self.assertTrue(result.wasSuccessful(), result.__dict__)
