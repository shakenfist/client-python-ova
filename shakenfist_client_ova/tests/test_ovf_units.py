import testtools

from shakenfist_client_ova import ovf
from shakenfist_client_ova.ovf import units


class BytesPerUnitTestCase(testtools.TestCase):
    def test_units_producers_write(self):
        # Every byte unit seen in the committed fixtures and the upstream corpus.
        for text, expected in (
                ('byte', 1),
                ('byte * 2^20', 2 ** 20),
                ('byte * 2 ^ 20', 2 ** 20),
                ('byte*1024*1024', 2 ** 20),
                ('byte * 2^30', 2 ** 30),
                ('byte*2^30', 2 ** 30),
                ('byte * 2 ^ 30', 2 ** 30),
                ('MegaBytes', 2 ** 20)):
            self.assertEqual(expected, units.bytes_per_unit(text), text)

    def test_returns_an_int(self):
        self.assertIsInstance(units.bytes_per_unit('byte * 2^20'), int)

    def test_legacy_names_are_powers_of_two(self):
        self.assertEqual(2 ** 10, units.bytes_per_unit('KiloBytes'))
        self.assertEqual(2 ** 20, units.bytes_per_unit('MegaBytes'))
        self.assertEqual(2 ** 30, units.bytes_per_unit('GigaBytes'))
        self.assertEqual(2 ** 30, units.bytes_per_unit(' gigabytes '))

    def test_base_in_any_case(self):
        for text in ('Byte * 2^20', 'BYTE*2^20', ' byte * 2^20 '):
            self.assertEqual(2 ** 20, units.bytes_per_unit(text), text)

    def test_powers_of_ten_and_integers(self):
        self.assertEqual(10 ** 9, units.bytes_per_unit('byte * 10^9'))
        self.assertEqual(512, units.bytes_per_unit('byte * 512'))
        self.assertEqual(2 ** 10 * 10 ** 3 * 4, units.bytes_per_unit('byte * 2^10 * 10^3 * 4'))
        self.assertEqual(1, units.bytes_per_unit('byte * 2^0'))

    def test_refused(self):
        for text in (
                # Not a byte count: the base is not a byte.
                'hertz * 10^6', 'hertz * 10^9', 'Hertz*10^9', 'bytes', 'bit * 8', 'count', '1', 'MegaHertz',
                # A missing, negative or fractional exponent, or another power.
                'byte * 2^', 'byte * 2^-1', 'byte * 10^-3', 'byte * 2^1.5', 'byte * 3^2', 'byte * ^20',
                # A multiplier that is not a positive integer, or is missing.
                'byte * 0', 'byte * -1', 'byte * 1.5', 'byte *', 'byte * * 2', 'byte / 2',
                # Spaces inside a number change it, so are refused.
                'byte * 2^2 0', 'byte * 10 24',
                # Empty, or a legacy name used as a base.
                '', ' ', 'MegaBytes * 2'):
            e = self.assertRaises(ovf.UnknownAllocationUnitError, units.bytes_per_unit, text)
            self.assertIn('"%s"' % text, str(e))

    def test_message(self):
        e = self.assertRaises(ovf.UnknownAllocationUnitError, units.bytes_per_unit, 'hertz * 10^6')
        self.assertEqual(
            'Unknown allocation unit "hertz * 10^6": only a byte count, such as "byte * 2^20", is understood', str(e))

    def test_factor_is_bounded(self):
        self.assertEqual(2 ** 128, units.bytes_per_unit('byte * 2^128'))
        for text in ('byte * 2^129', 'byte * 10^999', 'byte * 2^64 * 2^65', 'byte * 2^1000',
                     'byte * ' + '9' * 41):
            self.assertRaises(ovf.UnknownAllocationUnitError, units.bytes_per_unit, text)
