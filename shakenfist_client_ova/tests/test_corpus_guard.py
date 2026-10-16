"""The descriptor corpus tier fails, rather than skips, when a corpus is missing.

A skipped corpus test looks like a clean run, so the tier's guard must fail. This runs offline: the corpus cache is
pointed at an empty temporary directory, so the real .cache/ovf-corpora and the network are never touched.
"""

import os
import tempfile
from unittest import mock

import testtools

# The module is imported, not its test cases, so that the loader does not collect them from here.
from shakenfist_client_ova.corpus_tests import test_descriptor_corpus as corpus


class CorpusGuardTestCase(testtools.TestCase):
    def _empty_cache(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        patcher = mock.patch.object(corpus, 'CACHE', scratch.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        return scratch.name

    def _directories(self, cache):
        """Create the pinned subdirectory of each corpus under cache, holding no files."""
        for repo, (sha, subdirectory) in corpus.read_pins().items():
            os.makedirs(os.path.join(cache, '%s-%s' % (repo, sha), *subdirectory.split('/')))

    def test_empty_cache_is_unavailable(self):
        self._empty_cache()
        self.assertRaises(corpus.CorpusUnavailable, corpus.corpus_directories)

    def test_directories_without_descriptors_are_unavailable(self):
        self._directories(self._empty_cache())
        self.assertRaises(corpus.CorpusUnavailable, corpus.corpus_directories)

    def _run_corpus_test(self):
        result = testtools.TestResult()
        corpus.DescriptorCorpusTestCase('test_curated_descriptors_exist').run(result)
        return result

    def _assert_failed(self, result):
        self.assertEqual(1, result.testsRun)
        self.assertEqual(1, len(result.failures), 'expected a failure; got %r' % (result.__dict__,))
        self.assertEqual({}, result.skip_reasons)
        self.assertEqual([], result.errors)
        self.assertIn('not fetched', result.failures[0][1])

    def test_corpus_test_fails_when_cache_is_empty(self):
        self._empty_cache()
        self._assert_failed(self._run_corpus_test())

    def test_corpus_test_fails_when_directories_hold_no_descriptors(self):
        self._directories(self._empty_cache())
        self._assert_failed(self._run_corpus_test())
