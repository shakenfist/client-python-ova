import hashlib

import testtools

from shakenfist_client_ova import ovf


SHA1 = hashlib.sha1(b'disk').hexdigest()
SHA256 = hashlib.sha256(b'disk').hexdigest()
SHA512 = hashlib.sha512(b'disk').hexdigest()


class ParseManifestTestCase(testtools.TestCase):
    def test_each_form(self):
        manifest = ovf.parse_manifest('\n'.join([
            'SHA256(disk1.vmdk)= %s' % SHA256,                # ovftool
            'SHA1 (myvm-disk001.vmdk) = %s' % SHA1,           # VirtualBox
            'SHA1(wazuh-4.9.1.ovf) = %s' % SHA1,              # AWS
            '',
        ]).encode())
        self.assertEqual(
            [ovf.ManifestEntry(name='disk1.vmdk', algorithm='sha256', digest=SHA256),
             ovf.ManifestEntry(name='myvm-disk001.vmdk', algorithm='sha1', digest=SHA1),
             ovf.ManifestEntry(name='wazuh-4.9.1.ovf', algorithm='sha1', digest=SHA1)],
            manifest.entries)

    def test_each_algorithm_in_either_case(self):
        for algorithm, digest in (('SHA1', SHA1), ('SHA256', SHA256), ('SHA512', SHA512)):
            for written in (algorithm, algorithm.lower(), algorithm.capitalize()):
                manifest = ovf.parse_manifest(('%s(a.vmdk)= %s\n' % (written, digest)).encode())
                self.assertEqual([ovf.ManifestEntry(name='a.vmdk', algorithm=algorithm.lower(), digest=digest)],
                                 manifest.entries, written)

    def test_a_leading_byte_order_mark_is_ignored(self):
        manifest = ovf.parse_manifest(b'\xef\xbb\xbf' + ('SHA1(a.vmdk)= %s\n' % SHA1).encode())
        self.assertEqual([ovf.ManifestEntry(name='a.vmdk', algorithm='sha1', digest=SHA1)], manifest.entries)

    def test_a_byte_order_mark_elsewhere_is_refused(self):
        data = ('SHA1(a.vmdk)= %s\n' % SHA1).encode() + b'\xef\xbb\xbf' + ('SHA1(b.vmdk)= %s\n' % SHA1).encode()
        e = self.assertRaises(ovf.ManifestError, ovf.parse_manifest, data)
        self.assertIn('line 2', str(e))

    def test_keeps_entries_in_order(self):
        manifest = ovf.parse_manifest(('SHA1(b.vmdk)= %s\nSHA1(a.ovf)= %s\nSHA1(c.iso)= %s\n'
                                       % (SHA1, SHA1, SHA1)).encode())
        self.assertEqual(['b.vmdk', 'a.ovf', 'c.iso'], [entry.name for entry in manifest.entries])

    def test_blank_lines_are_skipped(self):
        manifest = ovf.parse_manifest(('\nSHA1(a.vmdk)= %s\n\n\nSHA1(b.vmdk)= %s\n\n' % (SHA1, SHA1)).encode())
        self.assertEqual(['a.vmdk', 'b.vmdk'], [entry.name for entry in manifest.entries])

    def test_empty_manifest(self):
        self.assertEqual([], ovf.parse_manifest(b'').entries)

    def test_missing_final_newline(self):
        manifest = ovf.parse_manifest(('SHA1(a.vmdk)= %s\nSHA1(b.vmdk)= %s' % (SHA1, SHA1)).encode())
        self.assertEqual(['a.vmdk', 'b.vmdk'], [entry.name for entry in manifest.entries])

    def test_upper_case_hex_is_kept_as_written(self):
        manifest = ovf.parse_manifest(('SHA256(a.vmdk)= %s\n' % SHA256.upper()).encode())
        self.assertEqual(SHA256.upper(), manifest.entries[0].digest)

    def test_mixed_case_hex(self):
        digest = SHA1[:20].upper() + SHA1[20:]
        manifest = ovf.parse_manifest(('SHA1(a.vmdk)= %s\n' % digest).encode())
        self.assertEqual(digest, manifest.entries[0].digest)

    def test_carriage_return_before_newline_is_ignored(self):
        manifest = ovf.parse_manifest(('SHA1(a.vmdk)= %s\r\n\r\nSHA1 (b.vmdk) = %s\r\n' % (SHA1, SHA1)).encode())
        self.assertEqual(
            [ovf.ManifestEntry(name='a.vmdk', algorithm='sha1', digest=SHA1),
             ovf.ManifestEntry(name='b.vmdk', algorithm='sha1', digest=SHA1)],
            manifest.entries)

    def test_only_one_carriage_return_is_ignored(self):
        e = self.assertRaises(ovf.ManifestError, ovf.parse_manifest, ('SHA1(a.vmdk)= %s\r\r\n' % SHA1).encode())
        self.assertIn('Manifest line 1 gives "a.vmdk" the SHA1 digest', str(e))

    def test_carriage_return_without_a_newline_is_part_of_the_digest(self):
        e = self.assertRaises(ovf.ManifestError, ovf.parse_manifest, ('SHA1(a.vmdk)= %s\r' % SHA1).encode())
        self.assertEqual('Manifest line 1 gives "a.vmdk" the SHA1 digest "%s\r", which is not 40 hexadecimal digits'
                         % SHA1, str(e))

    def test_virtualbox_spacing(self):
        manifest = ovf.parse_manifest(('SHA1 (myvm-disk001.vmdk) = %s\nSHA256 (myvm.ovf) = %s\n'
                                       % (SHA1, SHA256)).encode())
        self.assertEqual(
            [ovf.ManifestEntry(name='myvm-disk001.vmdk', algorithm='sha1', digest=SHA1),
             ovf.ManifestEntry(name='myvm.ovf', algorithm='sha256', digest=SHA256)],
            manifest.entries)

    def test_other_spacing(self):
        for line in ('SHA1(a.vmdk)=%s', 'SHA1  (a.vmdk)  =  %s', 'SHA1(a.vmdk) =%s'):
            manifest = ovf.parse_manifest((line % SHA1).encode())
            self.assertEqual([ovf.ManifestEntry(name='a.vmdk', algorithm='sha1', digest=SHA1)],
                             manifest.entries, line)

    def test_names_keep_their_brackets_and_spaces(self):
        manifest = ovf.parse_manifest(('SHA1(my disk (1).vmdk)= %s\n' % SHA1).encode())
        self.assertEqual('my disk (1).vmdk', manifest.entries[0].name)

    def test_unknown_algorithm(self):
        for algorithm in ('MD5', 'SHA384', 'SHA-256', 'sha3_256'):
            e = self.assertRaises(ovf.ManifestError, ovf.parse_manifest,
                                  ('SHA1(a.ovf)= %s\n%s(a.vmdk)= %s\n' % (SHA1, algorithm, SHA256)).encode())
            self.assertEqual('Manifest line 2 uses the algorithm "%s", which is not SHA1, SHA256 or SHA512'
                             % algorithm, str(e))

    def test_digest_of_the_wrong_length(self):
        for algorithm, digest, length in (('SHA1', SHA1[:-1], 40), ('SHA1', SHA256, 40), ('SHA256', SHA1, 64),
                                          ('SHA256', SHA256 + '0', 64), ('SHA512', SHA256, 128)):
            e = self.assertRaises(ovf.ManifestError, ovf.parse_manifest,
                                  ('%s(a.vmdk)= %s\n' % (algorithm, digest)).encode())
            self.assertEqual('Manifest line 1 gives "a.vmdk" the %s digest "%s", which is not %d hexadecimal digits'
                             % (algorithm, digest, length), str(e))

    def test_digest_with_a_character_that_is_not_hex(self):
        for digest in (SHA1[:-1] + 'g', ' ' * 40, SHA1[:-1] + ' ', '0x' + SHA1[2:], SHA1[:-1] + '٠'):
            e = self.assertRaises(ovf.ManifestError, ovf.parse_manifest, ('SHA1(a.vmdk)= %s\n' % digest).encode())
            self.assertIn('which is not 40 hexadecimal digits', str(e), repr(digest))

    def test_empty_digest(self):
        e = self.assertRaises(ovf.ManifestError, ovf.parse_manifest, b'SHA1(a.vmdk)= \n')
        self.assertEqual('Manifest line 1 gives "a.vmdk" the SHA1 digest "", which is not 40 hexadecimal digits',
                         str(e))

    def test_repeated_name(self):
        e = self.assertRaises(ovf.ManifestError, ovf.parse_manifest,
                              ('SHA1(a.vmdk)= %s\n\nSHA1(b.vmdk)= %s\nSHA256(a.vmdk)= %s\n'
                               % (SHA1, SHA1, SHA256)).encode())
        self.assertEqual('Manifest line 4 repeats "a.vmdk", already given by line 1', str(e))

    def test_repeated_identical_entry(self):
        e = self.assertRaises(ovf.ManifestError, ovf.parse_manifest, ('SHA1(a.vmdk)= %s\n' % SHA1 * 2).encode())
        self.assertEqual('Manifest line 2 repeats "a.vmdk", already given by line 1', str(e))

    def test_names_are_compared_as_written(self):
        manifest = ovf.parse_manifest(('SHA1(a.vmdk)= %s\nSHA1(./a.vmdk)= %s\nSHA1(A.vmdk)= %s\n'
                                       % (SHA1, SHA1, SHA1)).encode())
        self.assertEqual(['a.vmdk', './a.vmdk', 'A.vmdk'], [entry.name for entry in manifest.entries])

    def test_malformed_line(self):
        e = self.assertRaises(ovf.ManifestError, ovf.parse_manifest,
                              ('SHA1(a.vmdk)= %s\nnot a manifest line\n' % SHA1).encode())
        self.assertEqual('Manifest line 2 is "not a manifest line", which is not ALGORITHM(name)= digest', str(e))

    def test_other_malformed_lines(self):
        for line in ('SHA1(a.vmdk) %s' % SHA1, 'SHA1 a.vmdk = %s' % SHA1, 'SHA1()= %s' % SHA1,
                     '(a.vmdk)= %s' % SHA1, ' SHA1(a.vmdk)= %s' % SHA1):
            e = self.assertRaises(ovf.ManifestError, ovf.parse_manifest, (line + '\n\n').encode())
            self.assertIn('which is not ALGORITHM(name)= digest', str(e), repr(line))

    def test_not_utf8(self):
        e = self.assertRaises(ovf.ManifestError, ovf.parse_manifest,
                              ('SHA1 (\xff.vmdk) = %s\n' % SHA1).encode('latin-1'))
        self.assertEqual('ManifestError(UnicodeDecodeError)', ovf.outcome_name(e))
        self.assertIn('Could not parse the manifest: UnicodeDecodeError', str(e))

    def test_rule_errors_have_no_cause(self):
        e = self.assertRaises(ovf.ManifestError, ovf.parse_manifest, b'MD5(a.vmdk)= 00\n')
        self.assertEqual('ManifestError', ovf.outcome_name(e))
