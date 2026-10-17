import os
import re

import testtools

from shakenfist_client_ova import ovf
from shakenfist_client_ova.ovf import cim
from shakenfist_client_ova.ovf import errors
from shakenfist_client_ova.ovf import namespaces
from shakenfist_client_ova.ovf import quirks


VENDOR = os.path.join(os.path.dirname(__file__), 'fixtures', 'ovf', 'vendor')

NAMESPACE_DECLARATION_RE = re.compile(r'xmlns(?::[A-Za-z0-9_.-]+)?="([^"]*)"')


def _declared_namespaces(name):
    with open(os.path.join(VENDOR, name), encoding='utf-8') as f:
        return set(NAMESPACE_DECLARATION_RE.findall(f.read()))


class QuirksTestCase(testtools.TestCase):
    def test_virtualbox_namespaces_are_the_ones_virtualbox_writes(self):
        declared = _declared_namespaces('archiveteam-warrior-4.1.ovf')
        for alias in quirks.NAMESPACE_ALIASES:
            self.assertIn(alias, declared)

    def test_namespace_aliases_name_cim_classes(self):
        self.assertEqual(
            {namespaces.VIRTUALBOX_EPASD: namespaces.EPASD, namespaces.VIRTUALBOX_SASD: namespaces.SASD},
            quirks.NAMESPACE_ALIASES)
        for alias, namespace in quirks.NAMESPACE_ALIASES.items():
            self.assertIn(namespace, cim.PROPERTIES)
            self.assertNotIn(alias, cim.PROPERTIES)

    def test_instance_id_alias(self):
        self.assertEqual(set(cim.PROPERTIES), set(quirks.INSTANCE_ID_NAMESPACES))
        for namespace in quirks.INSTANCE_ID_NAMESPACES:
            canonical = quirks.ELEMENT_ALIASES[(namespace, 'InstanceId')]
            self.assertEqual('InstanceID', canonical)
            self.assertIn(canonical, cim.PROPERTIES[namespace])
        self.assertEqual(len(quirks.INSTANCE_ID_NAMESPACES), len(quirks.ELEMENT_ALIASES))

    def test_ovirt_namespace_is_the_one_ovirt_writes(self):
        self.assertEqual('http://www.ovirt.org/ovf', quirks.OVIRT_NAMESPACE)
        self.assertIn(quirks.OVIRT_NAMESPACE, _declared_namespaces('oracle-linux-9.8-olvm.ovf'))

    def test_envelope_namespaces(self):
        self.assertIn(namespaces.OVF_1, _declared_namespaces('vyos-1.2.1.ovf'))
        self.assertIn(namespaces.OVF_2, _declared_namespaces('archiveteam-warrior-4.1.ovf'))
        self.assertIn(namespaces.OVF_0_9, _declared_namespaces('tails-202607.ovf'))
        self.assertEqual(frozenset([namespaces.OVF_1, namespaces.OVF_2]), namespaces.OVF_ENVELOPES)


class NewErrorsTestCase(testtools.TestCase):
    def test_exported_and_documented(self):
        for name in ('UnsupportedEnvelopeError', 'VirtualSystemCollectionError', 'UnsupportedProducerError',
                     'MissingContentError', 'InvalidValueError', 'BrokenReferenceError'):
            cls = getattr(errors, name)
            self.assertIs(cls, getattr(ovf, name))
            self.assertIn(name, ovf.__all__)
            self.assertTrue(issubclass(cls, ovf.OVFError), name)
            self.assertTrue(cls.__doc__, name)
            self.assertEqual(name, ovf.outcome_name(cls('message')))
