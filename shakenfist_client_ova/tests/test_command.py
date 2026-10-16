import io
import os
import tarfile
import tempfile
from unittest import mock

from click.testing import CliRunner
import testtools

import shakenfist_client_ova as ova
from shakenfist_client_ova import _envelope_summary, _hardware_summary, ovf


FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures', 'ovf')

STREAM_OPTIMIZED = 'http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized'


def _fixture(name):
    with open(os.path.join(FIXTURES, name), 'rb') as f:
        return f.read()


class SummaryTestCase(testtools.TestCase):
    def test_envelope_summary_of_a_vendor_descriptor(self):
        envelope = ovf.parse_descriptor(_fixture('vendor/wazuh-4.9.1.ovf'))
        self.assertEqual(
            ['    Version: 1',
             '    System id: Wazuh v4.9.1 OVA',
             '    Operating system: id 101, type otherLinux64Guest, Linux - Amazon Linux 2',
             '    Product: TRIMMED, version 4.9.1',
             '    File file1: wazuh-4.9.1-disk-1.vmdk',
             '    Disk vmdisk1: 50 GiB, file file1, format ' + STREAM_OPTIMIZED,
             '    Network: VM Network',
             '    vCPUs: 4',
             '    Memory: 8192 MiB',
             '    Controller 3: ide',
             '    Controller 4: ide',
             '    NIC: E1000 on VM Network',
             '    Disk drive: Hard Disk 1 at address 0 on controller 4'],
            _envelope_summary(envelope, 1, envelope.virtual_system.id))

    def test_envelope_summary_with_two_controllers(self):
        envelope = ovf.parse_descriptor(_fixture('handwritten/two-controllers.ovf'))
        self.assertEqual(
            ['    Version: 1.0',
             '    System id: example-vm',
             '    Operating system: id 36, Linux',
             '    File file1: disk1.vmdk',
             '    File file2: disk2.vmdk',
             '    Disk vmdisk1: 10 GiB, file file1, format ' + STREAM_OPTIMIZED,
             '    Disk vmdisk2: 10 GiB, file file2, format ' + STREAM_OPTIMIZED,
             '    Network: VM Network',
             '    vCPUs: 1',
             '    Memory: 1024 MiB',
             '    Controller 3: scsi',
             '    Controller 6: ide',
             '    NIC: E1000 on VM Network',
             '    Disk drive: Hard disk 1 at address 0 on controller 3',
             '    Disk drive: Hard disk 2 at address 0 on controller 6'],
            _envelope_summary(envelope, envelope.version, envelope.virtual_system.id))

    def test_envelope_summary_names_the_product_but_not_its_prose(self):
        envelope = ovf.parse_descriptor(_fixture('handwritten/product-and-eula.ovf'))
        lines = _envelope_summary(envelope, envelope.version, envelope.virtual_system.id)
        self.assertEqual(
            ['    Operating system: id 36, Linux',
             '    Product: Example Appliance, version 1.0'],
            [line for line in lines if line.startswith(('    Operating', '    Product'))])
        self.assertNotIn('licence', '\n'.join(lines))

    def test_hardware_summary_shows_both_disk_drives(self):
        envelope = ovf.parse_descriptor(_fixture('handwritten/two-controllers.ovf'))
        lines = _hardware_summary(envelope.virtual_system.hardware[0])
        self.assertEqual(
            ['    Disk drive: Hard disk 1 at address 0 on controller 3',
             '    Disk drive: Hard disk 2 at address 0 on controller 6'],
            [line for line in lines if line.startswith('    Disk drive:')])


def _text(descriptor_name, old, new):
    """A hand-written descriptor, as bytes, with every occurrence of one string replaced."""
    text = _fixture(descriptor_name).decode()
    assert old in text, old
    return text.replace(old, new).encode()


PRODUCT_AND_EULA = 'handwritten/product-and-eula.ovf'
TWO_CONTROLLERS = 'handwritten/two-controllers.ovf'

LICENCE = 'This is invented licence text for a test fixture. It grants nothing and binds no one.'
REFUSAL = 'This appliance has a licence agreement, printed above. Re-run with --accept-eula to accept it.'
PROPERTY_WARNING = 'Warning: this appliance expects the following properties to be set at first boot'


class CommandTestCase(testtools.TestCase):
    def _import(self, descriptor, args=(), members=None):
        """Run ova import on a one-descriptor OVA, with extra archive members and options as given."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'x.ova')
            with tarfile.open(path, 'w') as archive:
                for member, data in [('x.ovf', descriptor)] + sorted((members or {}).items()):
                    info = tarfile.TarInfo(member)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))

            with mock.patch('shakenfist_client_ova.apiclient.Client') as client_class, \
                    mock.patch('shakenfist_client_ova.util') as util:
                result = CliRunner().invoke(ova.ova, ['import', path] + list(args), obj={})
        return result, client_class.return_value, util

    def assertNothingUploaded(self, client, util):
        client.check_capability.assert_not_called()
        client.blob_artifact.assert_not_called()
        util.checksum_with_progress_from_file_like_object.assert_not_called()
        util.upload_artifact_with_progress_file_like_object.assert_not_called()


class ImportCommandTestCase(CommandTestCase):
    def test_refused_descriptor_is_one_line(self):
        result, _, _ = self._import(_fixture('vendor/tails-202607.ovf'))
        self.assertEqual(1, result.exit_code)
        lines = [line for line in result.output.split('\n') if line.startswith('The descriptor is an OVF 0.9 envelope')]
        self.assertEqual(1, len(lines), result.output)
        self.assertNotIn('Traceback', result.output)

    def test_parseable_descriptor_prints_the_summary(self):
        result, client, util = self._import(_fixture('vendor/wazuh-4.9.1.ovf'))
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn('VM description:', result.output)
        self.assertIn('    Operating system: id 101, type otherLinux64Guest, Linux - Amazon Linux 2', result.output)
        self.assertIn('    Product: TRIMMED, version 4.9.1', result.output)
        self.assertNotIn('Licence agreement', result.output)
        self.assertNotIn('Warning', result.output)
        self.assertNothingUploaded(client, util)

    def test_unaccepted_licence_is_printed_and_refuses_the_import(self):
        result, client, util = self._import(_fixture(PRODUCT_AND_EULA))
        self.assertEqual(1, result.exit_code, result.output)
        self.assertIn(LICENCE, result.output)
        self.assertEqual(1, result.output.count('--accept-eula'), result.output)
        self.assertIn(REFUSAL, result.output)
        self.assertLess(result.output.index(LICENCE), result.output.index(REFUSAL))
        self.assertNotIn('Uploading disk images', result.output)
        self.assertNotIn('Traceback', result.output)
        self.assertNothingUploaded(client, util)

    def test_unaccepted_licence_refuses_before_the_property_warning(self):
        result, _, _ = self._import(_fixture(PRODUCT_AND_EULA))
        self.assertNotIn(PROPERTY_WARNING, result.output)

    def test_accepted_licence_is_printed_and_the_import_continues(self):
        result, client, util = self._import(_fixture(PRODUCT_AND_EULA), ['--accept-eula'])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn(LICENCE, result.output)
        self.assertNotIn(REFUSAL, result.output)
        self.assertIn('Uploading disk images...', result.output)

    def test_every_licence_is_printed(self):
        second = 'A second invented licence.'
        descriptor = _text(PRODUCT_AND_EULA, '</EulaSection>',
                           '</EulaSection><EulaSection><Info>Another</Info><License>%s</License></EulaSection>'
                           % second)
        result, client, util = self._import(descriptor)
        self.assertEqual(1, result.exit_code, result.output)
        self.assertIn(LICENCE, result.output)
        self.assertIn(second, result.output)
        self.assertNothingUploaded(client, util)

    def test_property_without_a_value_is_warned_of_by_key_and_label(self):
        result, _, _ = self._import(_fixture(PRODUCT_AND_EULA), ['--accept-eula'])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertEqual(1, result.output.count('Warning'), result.output)
        self.assertIn(PROPERTY_WARNING, result.output)
        self.assertIn('Shaken Fist cannot deliver them yet', result.output)
        self.assertIn('    hostname (Host name)', result.output)

    def test_property_with_an_empty_value_is_warned_of(self):
        descriptor = _text(PRODUCT_AND_EULA, 'ovf:userConfigurable="true"', 'ovf:userConfigurable="true" ovf:value=""')
        result, _, _ = self._import(descriptor, ['--accept-eula'])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn('    hostname (Host name)', result.output)

    def test_property_with_a_value_is_not_warned_of(self):
        descriptor = _text(PRODUCT_AND_EULA, 'ovf:userConfigurable="true"',
                           'ovf:userConfigurable="true" ovf:value="appliance"')
        result, _, _ = self._import(descriptor, ['--accept-eula'])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertNotIn('Warning', result.output)

    def test_property_the_user_cannot_configure_is_not_warned_of(self):
        descriptor = _text(PRODUCT_AND_EULA, 'ovf:userConfigurable="true"', 'ovf:userConfigurable="false"')
        result, _, _ = self._import(descriptor, ['--accept-eula'])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertNotIn('Warning', result.output)

    def test_property_without_a_label_is_warned_of_by_key(self):
        descriptor = _text(PRODUCT_AND_EULA, '<Label>Host name</Label>', '')
        result, _, _ = self._import(descriptor, ['--accept-eula'])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn('\n    hostname\n', result.output)

    def test_properties_of_every_product_are_warned_of_in_one_block(self):
        second = ('<ProductSection ovf:class="second"><Info>More</Info><Product>Second</Product>'
                  '<Property ovf:key="dns" ovf:type="string" ovf:userConfigurable="true"><Label>DNS</Label>'
                  '</Property></ProductSection>')
        descriptor = _text(PRODUCT_AND_EULA, '<EulaSection>', second + '<EulaSection>')
        result, _, _ = self._import(descriptor, ['--accept-eula'])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertEqual(1, result.output.count('Warning'), result.output)
        self.assertIn('    hostname (Host name)', result.output)
        self.assertIn('    dns (DNS)', result.output)


class UntrustedTextTestCase(CommandTestCase):
    """Text from the OVA reaches the terminal with its control characters made visible."""

    def _licence_import(self, licence):
        envelope = ovf.parse_descriptor(_fixture(PRODUCT_AND_EULA))
        envelope.virtual_system.eulas[0].license = licence
        with mock.patch('shakenfist_client_ova.ovf.parse_descriptor', return_value=envelope):
            return self._import(_fixture(PRODUCT_AND_EULA))

    def assertNoControlCharacters(self, output):
        for character in output:
            if character not in '\n\t':
                self.assertFalse(ord(character) < 0x20 or 0x7f <= ord(character) <= 0x9f,
                                 'U+%04X in %r' % (ord(character), output))

    def test_printable(self):
        self.assertEqual('a\\x1b[2Jb\\x07\\x9b\\x00\\x7f\\x0d\nc\td\u00a0', ova._printable(
            'a\x1b[2Jb\x07\x9b\x00\x7f\r\nc\td\u00a0'))

    def test_licence_escape_sequences_are_made_visible(self):
        result, _, _ = self._licence_import('Terms\x1b[2J and \x1b]0;evil\x07 more\nterms')
        self.assertEqual(1, result.exit_code, result.output)
        self.assertNotIn('\x1b', result.output)
        self.assertNotIn('\x07', result.output)
        self.assertIn('Terms\\x1b[2J and \\x1b]0;evil\\x07 more\nterms', result.output)
        self.assertNoControlCharacters(result.output)

    def test_c1_controls_and_carriage_returns_from_the_descriptor_are_made_visible(self):
        # XML 1.0 refuses ESC and BEL in a document, but allows the C1
        # controls, and a carriage return given as a character reference.
        descriptor = _text(PRODUCT_AND_EULA, LICENCE, 'Terms&#x9b;2J&#x9d;0;evil&#x9c;&#13;over')
        result, _, _ = self._import(descriptor)
        self.assertEqual(1, result.exit_code, result.output)
        self.assertIn('Terms\\x9b2J\\x9d0;evil\\x9c\\x0dover', result.output)
        self.assertNoControlCharacters(result.output)

    def test_error_messages_are_made_visible(self):
        error = ovf.InvalidValueError('Envelope/References/File@ovf:size is "\x1b]0;evil\x07", which is bad')
        with mock.patch('shakenfist_client_ova.ovf.parse_descriptor', side_effect=error):
            result, client, util = self._import(_fixture(PRODUCT_AND_EULA))
        self.assertEqual(1, result.exit_code, result.output)
        self.assertNotIn('\x1b', result.output)
        self.assertNotIn('\x07', result.output)
        self.assertIn('ovf:size is "\\x1b]0;evil\\x07", which is bad', result.output)
        self.assertNothingUploaded(client, util)

    def test_member_names_are_made_visible(self):
        result, _, _ = self._import(_fixture(TWO_CONTROLLERS), members={'evil\x1b[2J.vmdk': b'x'})
        self.assertIn('    Disk:     evil\\x1b[2J.vmdk', result.output)
        self.assertIn('evil\\x1b[2J.vmdk with size', result.output)
        self.assertNoControlCharacters(result.output)


# What each OVFError subclass is raised by. A value is the descriptor's bytes, or
# a function of the test case returning the descriptor and any extra archive members.
def _synthetic(old, new, name=TWO_CONTROLLERS):
    return lambda: (_text(name, old, new), None)


RAISERS = {
    ovf.ManifestError: lambda: (_fixture(TWO_CONTROLLERS), {'x.mf': b'this is not a manifest line\n'}),
    ovf.UnknownAllocationUnitError: _synthetic('byte * 2^30', 'hertz * 2^30'),
    ovf.UnsupportedHardwareError: _synthetic(
        '<rasd:ResourceType>10</rasd:ResourceType>', '<rasd:ResourceType>99</rasd:ResourceType>'),
    ovf.UnparsedContentError: lambda: (_fixture('handwritten/unknown-ovf-attribute.ovf'), None),
    ovf.MalformedDescriptorError: lambda: (_fixture(TWO_CONTROLLERS)[:400], None),
    ovf.EntityDeclarationError: lambda: (_fixture('handwritten/entity-declaration.ovf'), None),
    ovf.UnsupportedEnvelopeError: lambda: (_fixture('vendor/tails-202607.ovf'), None),
    ovf.VirtualSystemCollectionError: lambda: (_fixture('handwritten/virtual-system-collection.ovf'), None),
    ovf.UnsupportedProducerError: lambda: (_fixture('vendor/oracle-linux-9.8-olvm.ovf'), None),
    ovf.MissingContentError: _synthetic('<VirtualSystem ovf:id="example-vm">', '<VirtualSystem>'),
    ovf.InvalidValueError: _synthetic('ovf:capacity="10"', 'ovf:capacity="ten"'),
    ovf.BrokenReferenceError: _synthetic('ovf:fileRef="file1"', 'ovf:fileRef="nowhere"'),
}


class ErrorsTestCase(CommandTestCase):
    def _error_lines(self, output):
        """The non-blank lines printed after the list of archive members."""
        return [line for line in output.split('\n\n', 1)[1].split('\n') if line.strip()]

    def _message(self, error, descriptor, members):
        try:
            if error is ovf.ManifestError:
                ovf.parse_manifest(members['x.mf'])
            else:
                ovf.parse_descriptor(descriptor)
        except ovf.OVFError as e:
            return str(e)
        self.fail('%s was not raised' % error.__name__)

    def test_every_error_has_a_raiser(self):
        subclasses = set()
        pending = [ovf.OVFError]
        while pending:
            for subclass in pending.pop().__subclasses__():
                subclasses.add(subclass)
                pending.append(subclass)
        self.assertEqual(set(RAISERS), subclasses)

    def test_every_error_raises_its_error(self):
        for error, raiser in RAISERS.items():
            descriptor, members = raiser()
            if error is ovf.ManifestError:
                self.assertRaises(error, ovf.parse_manifest, members['x.mf'])
            else:
                self.assertRaises(error, ovf.parse_descriptor, descriptor)

    def test_every_error_is_a_line_and_an_exit(self):
        for error, raiser in sorted(RAISERS.items(), key=lambda item: item[0].__name__):
            if error is ovf.UnparsedContentError:
                continue
            descriptor, members = raiser()
            result, client, util = self._import(descriptor, members=members)
            self.assertEqual(1, result.exit_code, '%s: %s' % (error.__name__, result.output))
            self.assertNotIn('Traceback', result.output)
            self.assertNotIn('VM description', result.output)
            lines = self._error_lines(result.output)
            self.assertEqual(1, len(lines), '%s: %s' % (error.__name__, result.output))
            self.assertEqual(self._message(error, descriptor, members), lines[0])
            self.assertNothingUploaded(client, util)

    def test_unparsed_content_names_each_path_on_its_own_line(self):
        descriptor, members = RAISERS[ovf.UnparsedContentError]()
        result, client, util = self._import(descriptor, members=members)
        self.assertEqual(1, result.exit_code, result.output)
        self.assertNotIn('Traceback', result.output)
        lines = self._error_lines(result.output)
        self.assertEqual(ovf.descriptor.UNPARSED_HEADING, lines[0])
        self.assertEqual(['    Envelope/VirtualSystem@ovf:exampleUnknownAttribute'], lines[1:])
        self.assertNothingUploaded(client, util)
