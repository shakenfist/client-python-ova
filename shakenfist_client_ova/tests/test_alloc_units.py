import testtools

import shakenfist_client_ova as ova


class ParseAllocUnitsToBytesTestCase(testtools.TestCase):
    def test_no_units_is_bytes(self):
        self.assertEqual(1, ova._parse_alloc_units_to_bytes({}))

    def test_named_units(self):
        self.assertEqual(
            1024 * 1024,
            ova._parse_alloc_units_to_bytes({'rasd:AllocationUnits': 'MegaBytes'}))
        self.assertEqual(
            1024 * 1024 * 1024,
            ova._parse_alloc_units_to_bytes({'@v1:capacityAllocationUnits': 'GigaBytes'}))

    def test_unknown_unit_exits(self):
        self.assertRaises(
            SystemExit, ova._parse_alloc_units_to_bytes,
            {'rasd:AllocationUnits': 'Furlongs'})
