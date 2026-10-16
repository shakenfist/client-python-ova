import testtools

from shakenfist_client_ova import ovf


class ParseManifestTestCase(testtools.TestCase):
    def test_each_form(self):
        manifest = ovf.parse_manifest(b'\n'.join([
            b'SHA256(disk1.vmdk)= e1a654d69cf4112756899c6d639',      # ovftool
            b'SHA1 (myvm-disk001.vmdk) = aeb6a6c54fcc579d7a1',      # VirtualBox
            b'SHA1(wazuh-4.9.1.ovf) = 0123456789abcdef',            # AWS
            b'',
        ]))
        self.assertEqual(
            [ovf.ManifestEntry(name='disk1.vmdk', algorithm='sha256', digest='e1a654d69cf4112756899c6d639'),
             ovf.ManifestEntry(name='myvm-disk001.vmdk', algorithm='sha1', digest='aeb6a6c54fcc579d7a1'),
             ovf.ManifestEntry(name='wazuh-4.9.1.ovf', algorithm='sha1', digest='0123456789abcdef')],
            manifest.entries)

    def test_keeps_every_line(self):
        manifest = ovf.parse_manifest(b'SHA1 (a.vmdk) = 01\n\nSHA1 (a.vmdk) = 02\n')
        self.assertEqual(['01', '02'], [entry.digest for entry in manifest.entries])

    def test_crlf_is_kept_in_the_digest(self):
        # As today: the line is split on newlines only. Phase 4 rewrites this.
        manifest = ovf.parse_manifest(b'SHA1 (a.vmdk) = 01\r\n')
        self.assertEqual('01\r', manifest.entries[0].digest)

    def test_malformed_line(self):
        e = self.assertRaises(ovf.ManifestError, ovf.parse_manifest, b'SHA1 (a.vmdk) = 01\nnot a manifest line\n')
        self.assertEqual('Failed to parse manifest line: not a manifest line', str(e))

    def test_not_utf8(self):
        e = self.assertRaises(ovf.UnsupportedDescriptorError, ovf.parse_manifest, b'SHA1 (\xff.vmdk) = 01\n')
        self.assertEqual('UnsupportedDescriptorError(UnicodeDecodeError)', ovf.outcome_name(e))
        self.assertIn('Could not parse the manifest: UnicodeDecodeError', str(e))
