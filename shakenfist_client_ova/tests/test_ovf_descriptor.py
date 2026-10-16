import os
from unittest import mock

import testtools

from shakenfist_client_ova import ovf


FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures', 'ovf')


class ParseDescriptorValueErrorTestCase(testtools.TestCase):
    def test_entity_declaration_is_named(self):
        with open(os.path.join(FIXTURES, 'handwritten', 'entity-declaration.ovf'), 'rb') as f:
            data = f.read()
        e = self.assertRaises(ovf.EntityDeclarationError, ovf.parse_descriptor, data)
        self.assertEqual('EntityDeclarationError', ovf.outcome_name(e))

    def test_other_value_error_is_unsupported(self):
        with mock.patch('shakenfist_client_ova.ovf.descriptor.xmltodict.parse',
                        side_effect=ValueError('something else')):
            e = self.assertRaises(ovf.UnsupportedDescriptorError, ovf.parse_descriptor, b'<a/>')
        self.assertEqual('UnsupportedDescriptorError(ValueError)', ovf.outcome_name(e))
