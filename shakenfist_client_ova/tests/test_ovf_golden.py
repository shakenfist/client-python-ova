"""Golden tests: the parser's outcome on every committed descriptor matches its expected file.

There is one test method per descriptor, generated below, so that each passes or
fails under its own name. See golden.py for the expected file format and for
OVF_UPDATE_EXPECTED.
"""

import os

import testtools

from shakenfist_client_ova.tests import golden


class GoldenTestCase(testtools.TestCase):
    def test_every_descriptor_has_an_expected_file_and_no_other_exists(self):
        descriptors = {golden.expected_path(p) for p in golden.descriptor_paths()}
        expected = set(golden.expected_paths())
        root = golden.FIXTURE_ROOT
        self.assertEqual(
            [], sorted(os.path.relpath(p, root) for p in descriptors - expected),
            'descriptors without an expected file')
        self.assertEqual(
            [], sorted(os.path.relpath(p, root) for p in expected - descriptors),
            'expected files without a descriptor')

    def test_descriptors_were_found(self):
        # A guard against the fixture directory moving and every generated test silently vanishing.
        self.assertTrue(golden.descriptor_paths())


def _make_test(descriptor_path):
    def test(self):
        golden.check(self, descriptor_path)
    return test


def _generate():
    for descriptor_path in golden.descriptor_paths():
        name = golden.test_name(descriptor_path)
        if hasattr(GoldenTestCase, name):
            raise RuntimeError('Two descriptors map to the test name %s' % name)
        setattr(GoldenTestCase, name, _make_test(descriptor_path))


_generate()
