import testtools

from shakenfist_client_ova.ovf import cim
from shakenfist_client_ova.ovf import namespaces


# Every CIM property seen on a hardware item in the committed fixtures and the
# upstream corpus, other than oVirt's extensions and the rasd:Unknown of
# deliberately invalid descriptors.
PROPERTIES_SEEN_ON_ITEMS = frozenset([
    'ResourceType', 'ElementName', 'InstanceID', 'Description', 'AddressOnParent', 'Parent', 'ResourceSubType',
    'HostResource', 'Address', 'AutomaticAllocation', 'VirtualQuantity', 'AllocationUnits', 'Connection', 'Caption',
    'Reservation', 'Weight', 'Limit', 'VirtualQuantityUnits',
])

CLASSES = {
    # namespace: (read, unused, refused, number of properties in the DMTF schema)
    namespaces.RASD: (cim.RASD_READ, cim.RASD_UNUSED, frozenset(), 29),
    namespaces.SASD: (cim.SASD_READ, cim.SASD_UNUSED, cim.SASD_REFUSED, 38),
    namespaces.EPASD: (cim.EPASD_READ, cim.EPASD_UNUSED, cim.EPASD_REFUSED, 51),
    namespaces.VSSD: (cim.VSSD_READ, cim.VSSD_UNUSED, frozenset(), 27),
}


class CimPropertiesTestCase(testtools.TestCase):
    def test_every_class_is_listed(self):
        self.assertEqual(set(CLASSES), set(cim.PROPERTIES))
        self.assertEqual(set(CLASSES), set(cim.UNUSED))

    def test_read_unused_and_refused_partition_the_class(self):
        for namespace, (read, unused, refused, count) in CLASSES.items():
            self.assertEqual(frozenset(), read & unused, namespace)
            self.assertEqual(frozenset(), read & refused, namespace)
            self.assertEqual(frozenset(), unused & refused, namespace)
            self.assertEqual(read | unused | refused, cim.PROPERTIES[namespace], namespace)
            self.assertEqual(unused, cim.UNUSED[namespace], namespace)
            self.assertEqual(count, len(cim.PROPERTIES[namespace]), namespace)

    def test_sets_hold_strings(self):
        for namespace, properties in cim.PROPERTIES.items():
            self.assertIsInstance(properties, frozenset)
            for name in properties:
                self.assertIsInstance(name, str)
                self.assertTrue(name.isidentifier(), name)

    def test_item_classes_hold_every_property_seen(self):
        for namespace in (namespaces.RASD, namespaces.SASD, namespaces.EPASD):
            self.assertEqual(frozenset(), PROPERTIES_SEEN_ON_ITEMS - cim.PROPERTIES[namespace], namespace)

    def test_storage_and_ethernet_are_resource_allocation_subclasses(self):
        rasd = cim.PROPERTIES[namespaces.RASD]
        for namespace in (namespaces.SASD, namespaces.EPASD):
            self.assertTrue(rasd < cim.PROPERTIES[namespace], namespace)
            self.assertEqual(cim.RASD_READ, CLASSES[namespace][0], namespace)
            self.assertTrue(cim.RASD_UNUSED <= cim.UNUSED[namespace], namespace)

    def test_guest_visible_properties_are_refused(self):
        # A read-only disk, the block size the guest sees, and a NIC's VLAN
        # and promiscuous policy change the guest, so they are never unused.
        for namespace, name in ((namespaces.SASD, 'Access'), (namespaces.SASD, 'VirtualResourceBlockSize'),
                                (namespaces.EPASD, 'PortVID'), (namespaces.EPASD, 'Promiscuous')):
            self.assertNotIn(name, cim.UNUSED[namespace], namespace)
            self.assertIn(name, cim.PROPERTIES[namespace], namespace)

    def test_non_standard_names_are_not_properties(self):
        for namespace, properties in cim.PROPERTIES.items():
            for name in ('Unknown', 'cpu_per_socket', 'UsbPolicy', 'InstanceId', 'resourcetype'):
                self.assertNotIn(name, properties, namespace)

    def test_what_the_parser_reads(self):
        self.assertEqual(
            frozenset([
                'ResourceType', 'ResourceSubType', 'InstanceID', 'Parent', 'AddressOnParent', 'HostResource',
                'VirtualQuantity', 'AllocationUnits', 'VirtualQuantityUnits', 'Connection', 'ElementName']),
            cim.RASD_READ)
        self.assertEqual(frozenset(['VirtualSystemType', 'VirtualSystemIdentifier']), cim.VSSD_READ)

    def test_quantity_units_are_read(self):
        # VirtualQuantityUnits changes what VirtualQuantity means, so it must
        # never be ignored as unused.
        for namespace in (namespaces.RASD, namespaces.SASD, namespaces.EPASD):
            self.assertNotIn('VirtualQuantityUnits', cim.UNUSED[namespace], namespace)
