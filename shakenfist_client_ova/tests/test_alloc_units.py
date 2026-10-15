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

    def test_power_of_two_units(self):
        # 'byte * 2^N' is a power of two, not 2 XOR N: XOR gave 22 for
        # 2^20 and 28 for 2^30 (#1).
        self.assertEqual(
            1024 * 1024,
            ova._parse_alloc_units_to_bytes({'rasd:AllocationUnits': 'byte * 2^20'}))
        self.assertEqual(
            1024 * 1024 * 1024,
            ova._parse_alloc_units_to_bytes({'@v1:capacityAllocationUnits': 'byte * 2^30'}))
        self.assertEqual(
            1, ova._parse_alloc_units_to_bytes({'rasd:AllocationUnits': 'byte * 2^0'}))
