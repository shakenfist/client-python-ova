import testtools

from shakenfist_client_ova.ovf import descriptor
from shakenfist_client_ova.ovf import UnknownAllocationUnitError


class ParseAllocUnitsToBytesTestCase(testtools.TestCase):
    def test_no_units_is_bytes(self):
        self.assertEqual(1, descriptor._parse_alloc_units_to_bytes({}))

    def test_named_units(self):
        self.assertEqual(
            1024 * 1024,
            descriptor._parse_alloc_units_to_bytes({'rasd:AllocationUnits': 'MegaBytes'}))
        self.assertEqual(
            1024 * 1024 * 1024,
            descriptor._parse_alloc_units_to_bytes({'@v1:capacityAllocationUnits': 'GigaBytes'}))

    def test_unknown_unit_raises(self):
        e = self.assertRaises(
            UnknownAllocationUnitError, descriptor._parse_alloc_units_to_bytes,
            {'rasd:AllocationUnits': 'Furlongs'})
        # Today's two lines: the unit, then the element's repr.
        self.assertEqual(
            'Unknown allocation unit: "Furlongs"\n{\'rasd:AllocationUnits\': \'Furlongs\'}', str(e))

    def test_power_of_two_units(self):
        # 'byte * 2^N' is a power of two, not 2 XOR N: XOR gave 22 for
        # 2^20 and 28 for 2^30 (#1).
        self.assertEqual(
            1024 * 1024,
            descriptor._parse_alloc_units_to_bytes({'rasd:AllocationUnits': 'byte * 2^20'}))
        self.assertEqual(
            1024 * 1024 * 1024,
            descriptor._parse_alloc_units_to_bytes({'@v1:capacityAllocationUnits': 'byte * 2^30'}))
        self.assertEqual(
            1, descriptor._parse_alloc_units_to_bytes({'rasd:AllocationUnits': 'byte * 2^0'}))
