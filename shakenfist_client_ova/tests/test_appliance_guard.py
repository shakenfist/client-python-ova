"""The appliance corpus tier fails, rather than skips, when its corpus is missing or incomplete.

A skipped corpus test looks like a clean run, so the tier's guard must fail. This runs offline: APPLIANCE_CORPUS is
pointed at a temporary directory of small invented files, so no real appliance is read. The check of an appliance's
descriptor against its trimmed fixture is tested here too, on synthetic OVAs built from the committed fixtures.
"""

import os
import tempfile
from unittest import mock

import testtools

# The module is imported, not its test cases, so that the loader does not collect them from here.
from shakenfist_client_ova.appliance_tests import test_appliance_corpus as corpus
from shakenfist_client_ova.tests import synthetic


POINTER = b'version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize 1024\n' % (b'0' * 64)

# Stands in for vendor prose, and must never appear in a failure.
MARKER = b'MARKER-VENDOR-TEXT'


def _committed_fixture(name):
    with open(os.path.join(corpus.VENDOR_FIXTURES, name + corpus.FIXTURE_SUFFIX), 'rb') as f:
        return f.read()


class ApplianceGuardTestCase(testtools.TestCase):
    def _scratch(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        return scratch.name

    def _fixtures(self, fixtures):
        """A directory holding each of fixtures, a dict of name and descriptor bytes, which VENDOR_FIXTURES names."""
        directory = self._scratch()
        for name, data in fixtures.items():
            with open(os.path.join(directory, name + corpus.FIXTURE_SUFFIX), 'wb') as f:
                f.write(data)
        patcher = mock.patch.object(corpus, 'VENDOR_FIXTURES', directory)
        patcher.start()
        self.addCleanup(patcher.stop)
        return directory

    def _corpus(self, names=('a', 'b'), ova=b'not a pointer', provenance=None, fixtures=None):
        """A directory holding <name>.ova and <name>.provenance.json for each name, which APPLIANCE_CORPUS names.

        A trimmed fixture is made for each of fixtures, which defaults to names.
        """
        directory = self._scratch()
        for name in names:
            with open(os.path.join(directory, name + corpus.OVA_SUFFIX), 'wb') as f:
                f.write(ova)
            if provenance is None or name in provenance:
                with open(os.path.join(directory, name + corpus.PROVENANCE_SUFFIX), 'w') as f:
                    f.write('{"kind": "whole"}\n')
        self._fixtures({name: b'' for name in (names if fixtures is None else fixtures)})
        self._set(directory)
        return directory

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
        self._assert_unavailable('does not name a directory')

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

    def test_appliance_whose_test_name_is_another_fixture_test(self):
        self._corpus(names=('a', 'a-fixture'))
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

    def test_appliance_without_fixture_fails(self):
        self._corpus(names=sorted(corpus.read_expected()) + ['a'], fixtures=sorted(corpus.read_expected()))
        self._assert_fails('these appliances have no trimmed fixture')

    def test_fixture_without_appliance_fails(self):
        self._corpus(names=sorted(corpus.read_expected()), fixtures=sorted(corpus.read_expected()) + ['a'])
        self._assert_fails('these trimmed fixtures name no appliance in the corpus')

    def _check_fixture(self, descriptor, fixture, members=None):
        """The result of checking an appliance, a, whose OVA holds descriptor as a.ovf, against fixture.

        members, if given, replaces the OVA's members; fixture None gives no
        fixture.
        """
        directory = self._scratch()
        synthetic.build(os.path.join(directory, 'a' + corpus.OVA_SUFFIX),
                        [('a.ovf', descriptor)] if members is None else members)
        self._fixtures({} if fixture is None else {'a': fixture})

        class Case(corpus.ApplianceCorpusTestCase):
            def setUp(self):
                testtools.TestCase.setUp(self)
                self.directory = directory

            def runTest(self):
                self.check_fixture('a')

        result = testtools.TestResult()
        Case().run(result)
        self.assertEqual(1, result.testsRun)
        self.assertEqual([], result.errors)
        self.assertEqual({}, result.skip_reasons)
        return result

    def _assert_check_fails(self, result, fragment):
        self.assertEqual(1, len(result.failures), 'expected a failure; got %r' % (result.__dict__,))
        failure = result.failures[0][1]
        self.assertIn('a: ' + fragment, failure)
        self.assertNotIn(MARKER.decode('ascii'), failure)
        return failure

    def test_fixture_matching_once_prose_is_scrubbed(self):
        fixture = _committed_fixture('wazuh-4.9.1')
        result = self._check_fixture(fixture.replace(b'>TRIMMED<', b'>' + MARKER + b'<'), fixture)
        self.assertTrue(result.wasSuccessful(), result.__dict__)

    def test_fixture_differing_from_its_descriptor_fails(self):
        fixture = _committed_fixture('wazuh-4.9.1')
        # The VirtualSystem's id is not prose, and the model holds it as written: a rendered difference would show it.
        descriptor = fixture.replace(b'>TRIMMED<', b'>' + MARKER + b'<').replace(
            b'ovf:id="Wazuh v4.9.1 OVA"', b'ovf:id="' + MARKER + b'"')
        self._assert_check_fails(self._check_fixture(descriptor, fixture), 'the scrubbed models')

    def test_refused_fixture_with_its_descriptor_outcome(self):
        fixture = _committed_fixture('oracle-linux-9.8-olvm')
        result = self._check_fixture(fixture.replace(b'>TRIMMED<', b'>' + MARKER + b'<'), fixture)
        self.assertTrue(result.wasSuccessful(), result.__dict__)

    def test_fixture_with_another_outcome_fails(self):
        result = self._check_fixture(_committed_fixture('oracle-linux-9.8-olvm'), _committed_fixture('tails-202607'))
        self._assert_check_fails(
            result, 'its descriptor gives UnsupportedProducerError, but its trimmed fixture UnsupportedEnvelopeError')

    def test_parsing_descriptor_with_refused_fixture_fails(self):
        result = self._check_fixture(_committed_fixture('wazuh-4.9.1'), _committed_fixture('tails-202607'))
        self._assert_check_fails(
            result, 'its descriptor gives a model, but its trimmed fixture UnsupportedEnvelopeError')

    def test_missing_fixture_fails(self):
        result = self._check_fixture(_committed_fixture('wazuh-4.9.1'), None)
        self._assert_check_fails(result, 'reading its trimmed fixture gives FileNotFoundError')

    def test_unreadable_descriptor_fails(self):
        result = self._check_fixture(None, _committed_fixture('wazuh-4.9.1'), members=[('a.txt', MARKER)])
        self._assert_check_fails(result, 'its descriptor cannot be read: the open gives PackageLayoutError')
