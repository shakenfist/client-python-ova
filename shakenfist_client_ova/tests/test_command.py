import contextlib
import hashlib
import itertools
import os
import tarfile
import tempfile
from unittest import mock

from click.testing import CliRunner
from shakenfist_client import apiclient
from shakenfist_client import util as shakenfist_util
import testtools

import shakenfist_client_ova as ova
from shakenfist_client_ova import _envelope_summary, _hardware_summary, ovf
from shakenfist_client_ova.tests import synthetic


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


def _replace(data, old, new):
    """Bytes with every occurrence of the text old replaced by new, which must occur."""
    text = data.decode()
    assert old in text, old
    return text.replace(old, new).encode()


def _text(descriptor_name, old, new):
    """A hand-written descriptor, as bytes, with every occurrence of one string replaced."""
    return _replace(_fixture(descriptor_name), old, new)


PRODUCT_AND_EULA = 'handwritten/product-and-eula.ovf'
TWO_CONTROLLERS = 'handwritten/two-controllers.ovf'

GLANCE = os.path.join(os.path.dirname(__file__), 'fixtures', 'ova', 'imported', 'glance')

LICENCE = 'This is invented licence text for a test fixture. It grants nothing and binds no one.'
REFUSAL = 'This appliance has a licence agreement, printed above. Re-run with --accept-eula to accept it.'
PROPERTY_WARNING = 'Warning: this appliance expects the following properties to be set at first boot'
NO_MANIFEST = 'Warning: the OVA has no manifest, so the disks cannot be checked for corruption.'

# The two-disk descriptor with its files cut to five bytes, so that its disks
# are small and can differ from each other.
SMALL = _text(TWO_CONTROLLERS, 'ovf:size="1048576"', 'ovf:size="5"')
DISK1 = b'disk1'
DISK2 = b'disk2'
DISKS = [('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)]
FILE1 = 'ovf:href="disk1.vmdk" ovf:size="5"'

# The largest member _referenced() writes, so that a test never writes a real disk's size.
LARGEST_MEMBER = 16 * 1024 * 1024


def _digest(algorithm, data):
    return hashlib.new(algorithm.lower(), data).hexdigest()


def _manifest(members, algorithm='SHA256'):
    """A manifest giving each member, a (name, data) pair or a synthetic.Member, its digest in the algorithm."""
    pairs = [(member.name, member.data) if isinstance(member, synthetic.Member) else member for member in members]
    return ''.join('%s(%s)= %s\n' % (algorithm, name, _digest(algorithm, data)) for name, data in pairs).encode()


def _referenced(descriptor):
    """A member of zeros, of its ovf:size, for each File the descriptor references, or none if it does not parse."""
    try:
        envelope = ovf.descriptor.parse_descriptor(descriptor)
    except ovf.OVFError:
        return []
    members = []
    for file in envelope.files:
        size = file.size or 0
        assert size <= LARGEST_MEMBER, '%s is %d bytes: cut its ovf:size' % (file.href, size)
        members.append((file.href, bytes(size)))
    return members


def _members(descriptor, disks=None, algorithm='SHA256', manifest_name='x.mf', certificate=False, extra=()):
    """The members of an OVA of descriptor, in ovftool's order.

    These are x.ovf, then a manifest of the descriptor and the disks unless
    algorithm is None, then x.cert if certificate is set, then the disks, by
    default a member of zeros for each File, then the extra members.
    """
    if disks is None:
        disks = _referenced(descriptor)
    members = [('x.ovf', descriptor)]
    if algorithm is not None:
        members.append((manifest_name, _manifest(members + list(disks), algorithm)))
    if certificate:
        members.append(('x.cert', b'An invented certificate, which nothing checks.\n'))
    return members + list(disks) + list(extra)


def _archive(members, **kwargs):
    """A function writing an OVA of members at the path it is given, with synthetic.build()'s options."""
    return lambda path: synthetic.build(path, members, **kwargs)


class CommandTestCase(testtools.TestCase):
    def _import(self, descriptor, args=(), disks=None, algorithm='SHA256', manifest_name='x.mf', certificate=False,
                extra=(), **kwargs):
        """Run ova import on an OVA of descriptor, as _members() builds it, with options as given."""
        return self._run(_members(descriptor, disks=disks, algorithm=algorithm, manifest_name=manifest_name,
                                  certificate=certificate, extra=extra), args, **kwargs)

    def _run(self, archive, args=(), **kwargs):
        """Run ova import on an OVA, a list of members or a function writing one at a path, in a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'x.ova')
            if callable(archive):
                archive(path)
            else:
                synthetic.build(path, archive)
            return self._invoke(path, args, **kwargs)

    def _invoke(self, path, args=(), blob_search=False, blob=None, upload=None, progress=True):
        """Run ova import on the OVA at path, with the client and the upload helper mocked.

        The server has blob-search-by-hash if blob_search is set, and finds
        blob for every SHA-512. upload replaces the upload helper, which by
        default reads the disk to its end. With progress, tqdm is replaced by
        a recorder, so that no bar is drawn, and each bar is in self.bars.
        Every member the archive opens for reading is named in self.reads,
        every upload is in self.uploads, and path is self.path.
        """
        self.path = path
        self.reads = []
        self.uploads = []
        self.bars = []
        real_extractfile = tarfile.TarFile.extractfile

        def recording_extractfile(archive, member, *args, **kwargs):
            self.reads.append(member.name if isinstance(member, tarfile.TarInfo) else member)
            return real_extractfile(archive, member, *args, **kwargs)

        test = self

        class Progress:
            """A stand-in for tqdm, recording its arguments and how far it got."""

            def __init__(self, **kwargs):
                self.kwargs = kwargs
                self.n = 0
                test.bars.append(self)

            def __enter__(self):
                return self

            def __exit__(self, *exc_info):
                pass

            def update(self, n):
                self.n += n

        with contextlib.ExitStack() as stack:
            client_class = stack.enter_context(mock.patch('shakenfist_client_ova.apiclient.Client'))
            util = stack.enter_context(mock.patch('shakenfist_client_ova.util'))
            stack.enter_context(mock.patch.object(tarfile.TarFile, 'extractfile', recording_extractfile))
            if progress:
                stack.enter_context(mock.patch('shakenfist_client_ova.tqdm', Progress))
            client = client_class.return_value
            client.check_capability.return_value = blob_search
            client.get_blob_by_sha512.return_value = blob
            client.blob_artifact.side_effect = lambda name, blob_uuid, source_url: {'uuid': 'blob-' + name}
            util.upload_artifact_with_progress_file_like_object.side_effect = upload or self._upload
            result = CliRunner().invoke(ova.ova, ['import', path] + list(args), obj={})
        return result, client, util

    def _upload(self, client, name, f, size, source_url):
        """The upload helper's stand-in, which reads the disk as the helper does and records what it read."""
        data = b''
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            data += chunk
        self.uploads.append((name, data, size, source_url))
        return {'uuid': 'uploaded-' + name}

    def assertNothingUploaded(self, client, util):
        """Nothing was uploaded or looked up, and the server was not even asked what it can do."""
        client.check_capability.assert_not_called()
        self.assertNoArtifacts(client, util)

    def assertNoArtifacts(self, client, util):
        """No disk was uploaded or looked up, and no artifact was made."""
        client.get_blob_by_sha512.assert_not_called()
        client.blob_artifact.assert_not_called()
        client.create_upload.assert_not_called()
        client.upload_artifact.assert_not_called()
        util.upload_artifact_with_progress_file_like_object.assert_not_called()

    def assertNoDiskRead(self):
        """No member but the descriptor and manifest was opened for reading."""
        self.assertEqual([], [name for name in self.reads if name not in ('x.ovf', 'x.mf')])

    def _lines(self, output):
        """The non-blank lines of output."""
        return [line for line in output.split('\n') if line.strip()]


class ImportCommandTestCase(CommandTestCase):
    def test_refused_descriptor_is_one_line(self):
        result, _, _ = self._import(_fixture('vendor/tails-202607.ovf'))
        self.assertEqual(1, result.exit_code)
        lines = [line for line in result.output.split('\n') if line.startswith('The descriptor is an OVF 0.9 envelope')]
        self.assertEqual(1, len(lines), result.output)
        self.assertNotIn('Traceback', result.output)

    def test_parseable_descriptor_prints_the_summary(self):
        descriptor = _text('vendor/wazuh-4.9.1.ovf', 'ovf:size="3950369280"', 'ovf:size="5"')
        result, client, util = self._import(descriptor)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn('VM description:', result.output)
        self.assertIn('    Operating system: id 101, type otherLinux64Guest, Linux - Amazon Linux 2', result.output)
        self.assertIn('    Product: TRIMMED, version 4.9.1', result.output)
        self.assertNotIn('Licence agreement', result.output)
        self.assertNotIn('Warning', result.output)
        self.assertEqual(['Wazuh v4.9.1 OVA-vmdisk1'], [upload[0] for upload in self.uploads])

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
        self.assertNoDiskRead()

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


class ArchiveSummaryTestCase(CommandTestCase):
    def test_two_disks_with_a_manifest_and_a_certificate(self):
        result, client, util = self._import(SMALL, disks=DISKS, certificate=True)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertEqual(
            ['Archive members:',
             '    Descriptor: x.ovf',
             '    Manifest: x.mf',
             '    Certificate: x.cert',
             '    File file1: disk1.vmdk',
             '    File file2: disk2.vmdk',
             '',
             'Notice: the OVA has the certificate x.cert, whose signature was not checked.',
             '',
             'VM description:'],
            result.output.split('\n')[:10])
        self.assertEqual(
            ['Uploading disk images...',
             '',
             'disk1.vmdk with size 5 Bytes, as the artifact example-vm-vmdisk1',
             'Disk artifact is uploaded-example-vm-vmdisk1',
             '',
             'disk2.vmdk with size 5 Bytes, as the artifact example-vm-vmdisk2',
             'Disk artifact is uploaded-example-vm-vmdisk2',
             ''],
            result.output.split('\n')[-8:])
        self.assertIn('Checking disk images...\n'
                      '    disk1.vmdk: its SHA256 digest matches the manifest\n'
                      '    disk2.vmdk: its SHA256 digest matches the manifest\n', result.output)
        self.assertNotIn('Warning', result.output)
        # The hardware is described once, in the VM description.
        self.assertEqual(1, result.output.count('    vCPUs: 1'), result.output)

    def test_what_the_import_leaves_alone(self):
        descriptor = _replace(SMALL, '</References>',
                              '  <File ovf:id="file3" ovf:href="tools.iso"/>\n  </References>')
        descriptor = _replace(descriptor, '</DiskSection>',
                              '  <Disk ovf:diskId="vmdisk3" ovf:capacity="1" '
                              'ovf:capacityAllocationUnits="byte * 2^30"/>\n  </DiskSection>')
        disks = DISKS + [('tools.iso', b'an iso')]
        result, client, util = self._import(descriptor, disks=disks, extra=[
            ('README.txt', b'Read me.'), synthetic.directory('docs')])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn('    File file3: tools.iso, which no disk uses, so it is neither verified nor uploaded\n'
                      '    Disk vmdisk3: no file, so it is created empty at deployment and not uploaded\n'
                      '    Ignored, as nothing references it: README.txt\n\n', result.output)
        self.assertNotIn('docs', result.output)
        self.assertNotIn('tools.iso', self.reads)
        self.assertEqual(['example-vm-vmdisk1', 'example-vm-vmdisk2'], [upload[0] for upload in self.uploads])

    def test_no_manifest(self):
        result, client, util = self._import(SMALL, disks=DISKS, algorithm=None)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn('    Manifest: none\n    Certificate: none\n', result.output)
        self.assertEqual(1, result.output.count(NO_MANIFEST), result.output)
        self.assertEqual(1, result.output.count('Warning'), result.output)
        # Nothing can be checked and nothing looked up, so each disk is read only to upload it.
        self.assertNotIn('Checking disk images', result.output)
        self.assertEqual([], self.bars)
        self.assertEqual(['disk1.vmdk', 'disk2.vmdk'], [name for name in self.reads if name.endswith('.vmdk')])
        self.assertEqual([DISK1, DISK2], [upload[1] for upload in self.uploads])

    def test_no_manifest_with_blob_search(self):
        result, client, util = self._import(SMALL, disks=DISKS, algorithm=None, blob_search=True)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn(NO_MANIFEST, result.output)
        self.assertIn('Checking disk images...\n', result.output)
        self.assertNotIn('matches the manifest', result.output)
        self.assertEqual([mock.call(_digest('sha512', DISK1)), mock.call(_digest('sha512', DISK2))],
                         client.get_blob_by_sha512.call_args_list)

    def test_manifest_named_differently(self):
        result, client, util = self._import(SMALL, disks=DISKS, manifest_name='y.mf')
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn('    Manifest: y.mf\n', result.output)
        self.assertIn('\nWarning: the manifest y.mf is not named after the descriptor x.ovf, as an OVA\'s manifest '
                      'should be.\n', result.output)
        self.assertEqual(1, result.output.count('Warning'), result.output)

    def test_manifest_entries_naming_nothing(self):
        members = _members(SMALL, disks=DISKS + [('notes.txt', b'notes')])
        # notes.txt is in the manifest, but no File names it.
        result, client, util = self._run(members)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn('Warning: the manifest has entries for members the descriptor does not reference, which are '
                      'not checked:\n    notes.txt\n', result.output)
        self.assertIn('    Ignored, as nothing references it: notes.txt\n', result.output)
        self.assertNotIn('notes.txt', self.reads)


class VerificationTestCase(CommandTestCase):
    def test_digest_mismatch_on_the_second_disk_uploads_nothing(self):
        manifest = _manifest([('x.ovf', SMALL), ('disk1.vmdk', DISK1), ('disk2.vmdk', b'disk3')])
        result, client, util = self._run([('x.ovf', SMALL), ('x.mf', manifest)] + DISKS, blob_search=True)
        self.assertEqual(1, result.exit_code, result.output)
        self.assertNotIn('Traceback', result.output)
        self.assertNotIn('Uploading disk images', result.output)
        self.assertEqual(
            ['Checking disk images...',
             '    disk1.vmdk: its SHA256 digest matches the manifest',
             'The SHA256 digest of "disk2.vmdk" is %s, but the manifest "x.mf" gives %s'
             % (_digest('sha256', DISK2), _digest('sha256', b'disk3'))],
            self._lines(result.output)[-3:])
        self.assertNoArtifacts(client, util)

    def test_one_read_per_disk_with_a_manifest_and_blob_search(self):
        result, client, util = self._import(SMALL, disks=DISKS, blob_search=True, blob={'uuid': 'blob-uuid'})
        self.assertEqual(0, result.exit_code, result.output)
        # Each disk is read once, for both its manifest digest and the SHA-512
        # to look its blob up by, and the blob is reused, so it is not read again.
        self.assertEqual(['x.mf', 'x.ovf', 'disk1.vmdk', 'disk2.vmdk'], self.reads)
        self.assertEqual([mock.call(_digest('sha512', DISK1)), mock.call(_digest('sha512', DISK2))],
                         client.get_blob_by_sha512.call_args_list)
        self.assertIn('    disk2.vmdk: its SHA256 digest matches the manifest\n', result.output)
        self.assertEqual(
            [{'total': 5, 'unit': 'B', 'unit_scale': True, 'desc': 'Reading disk1.vmdk'},
             {'total': 5, 'unit': 'B', 'unit_scale': True, 'desc': 'Reading disk2.vmdk'}],
            [bar.kwargs for bar in self.bars])
        self.assertEqual([5, 5], [bar.n for bar in self.bars])

    def test_a_sha512_manifest_is_read_for_both_at_once(self):
        result, client, util = self._import(SMALL, disks=DISKS, algorithm='SHA512', blob_search=True)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn('    disk1.vmdk: its SHA512 digest matches the manifest\n', result.output)
        self.assertEqual([mock.call(_digest('sha512', DISK1)), mock.call(_digest('sha512', DISK2))],
                         client.get_blob_by_sha512.call_args_list)

    def test_a_disk_with_no_blob_is_read_again_to_upload_it(self):
        result, client, util = self._import(SMALL, disks=DISKS, blob_search=True)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertEqual(['x.mf', 'x.ovf', 'disk1.vmdk', 'disk2.vmdk', 'disk1.vmdk', 'disk2.vmdk'], self.reads)
        self.assertEqual(2, client.get_blob_by_sha512.call_count)
        self.assertEqual([DISK1, DISK2], [upload[1] for upload in self.uploads])
        client.blob_artifact.assert_not_called()

    def test_without_blob_search_nothing_is_looked_up(self):
        result, client, util = self._import(SMALL, disks=DISKS)
        self.assertEqual(0, result.exit_code, result.output)
        client.check_capability.assert_called_once_with('blob-search-by-hash')
        client.get_blob_by_sha512.assert_not_called()
        self.assertNotIn('Searching for a pre-existing blob', result.output)
        self.assertEqual([DISK1, DISK2], [upload[1] for upload in self.uploads])

    def test_blob_reuse(self):
        result, client, util = self._import(SMALL, disks=DISKS, blob_search=True, blob={'uuid': 'blob-uuid'})
        self.assertEqual(0, result.exit_code, result.output)
        self.assertEqual(2, result.output.count('Searching for a pre-existing blob with this hash...\n'
                                                'Disk is already present in the cluster\n'), result.output)
        url = 'ova://%s/' % os.path.abspath(self.path)
        self.assertEqual(
            [mock.call('example-vm-vmdisk1', 'blob-uuid', source_url=url + 'disk1.vmdk'),
             mock.call('example-vm-vmdisk2', 'blob-uuid', source_url=url + 'disk2.vmdk')],
            client.blob_artifact.call_args_list)
        self.assertIn('Disk artifact is blob-example-vm-vmdisk2\n', result.output)
        util.upload_artifact_with_progress_file_like_object.assert_not_called()

    def test_artifact_names_and_absolute_source_urls(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = synthetic.build(os.path.join(tmpdir, 'x.ova'), _members(SMALL, disks=DISKS))
            relative = os.path.relpath(path)
            self.assertFalse(os.path.isabs(relative))
            result, client, util = self._invoke(relative)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertEqual(
            [('example-vm-vmdisk1', DISK1, 5, 'ova://%s/disk1.vmdk' % path),
             ('example-vm-vmdisk2', DISK2, 5, 'ova://%s/disk2.vmdk' % path)],
            self.uploads)
        self.assertEqual([mock.call(client, 'example-vm-vmdisk1', mock.ANY, 5, 'ova://%s/disk1.vmdk' % path),
                          mock.call(client, 'example-vm-vmdisk2', mock.ANY, 5, 'ova://%s/disk2.vmdk' % path)],
                         util.upload_artifact_with_progress_file_like_object.call_args_list)

    def test_slash_in_an_artifact_name_is_refused_before_any_read(self):
        descriptor = _replace(SMALL, '<VirtualSystem ovf:id="example-vm">', '<VirtualSystem ovf:id="example/vm">')
        result, client, util = self._import(descriptor, disks=DISKS, blob_search=True)
        self.assertEqual(1, result.exit_code, result.output)
        self.assertNotIn('Traceback', result.output)
        self.assertEqual('The artifact name "example/vm-vmdisk1", made from the VirtualSystem\'s ovf:id and the '
                         'Disk\'s ovf:diskId, contains a /, which an artifact name may not',
                         self._lines(result.output)[-1])
        self.assertNoDiskRead()
        self.assertEqual([], self.bars)
        self.assertNothingUploaded(client, util)

    def test_archive_failing_during_the_upload(self):
        # The OVA loses its end after it has been checked, part way through
        # the second disk's upload.
        disk2 = b'0123456789' * 300000
        descriptor = _replace(SMALL, 'ovf:href="disk2.vmdk" ovf:size="5"', 'ovf:href="disk2.vmdk"')

        def shrinking_upload(client, name, f, size, source_url):
            if name.endswith('vmdisk2'):
                os.truncate(self.path, os.path.getsize(self.path) // 2)
            return self._upload(client, name, f, size, source_url)

        result, client, util = self._import(descriptor, disks=[('disk1.vmdk', DISK1), ('disk2.vmdk', disk2)],
                                            algorithm=None, upload=shrinking_upload)
        self.assertEqual(1, result.exit_code, result.output)
        self.assertNotIn('Traceback', result.output)
        self.assertTrue(self._lines(result.output)[-1].startswith(
            'Could not read "disk2.vmdk" from the OVA: ReadError: '), result.output)
        self.assertEqual(['example-vm-vmdisk1'], [upload[0] for upload in self.uploads])

    def test_upload_helper_seeks_back_for_a_retried_chunk(self):
        # shakenfist_client's own helper, which seeks the disk back to the
        # last chunk the server has when a chunk fails.
        disk2 = bytes(range(256)) * 64
        descriptor = _replace(SMALL, 'ovf:href="disk2.vmdk" ovf:size="5"', 'ovf:href="disk2.vmdk"')
        received = []
        failures = []

        def send_upload(upload_uuid, data):
            if len(received) == 1 and not failures:
                failures.append(data)
                raise apiclient.APIException('Failed', 'POST', '/upload', 500, '')
            received.append(data)
            return sum(len(chunk) for chunk in received)

        def upload(client, name, f, size, source_url):
            client.create_upload.return_value = {'uuid': 'upload-uuid', 'node': 'node'}
            client.send_upload.side_effect = send_upload
            client.upload_artifact.return_value = {'uuid': 'uploaded-' + name}
            received.clear()
            # The helper times each chunk, and a clock that does not move would make it divide by zero.
            with mock.patch.object(shakenfist_util, 'time') as clock:
                clock.time.side_effect = itertools.count()
                return shakenfist_util.upload_artifact_with_progress_file_like_object(
                    client, name, f, size, source_url)

        result, client, util = self._import(descriptor, disks=[('disk1.vmdk', DISK1), ('disk2.vmdk', disk2)],
                                            upload=upload)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertEqual(1, len(failures))
        self.assertEqual(disk2, b''.join(received))
        client.truncate_upload.assert_called_once_with('upload-uuid', len(received[0]))
        self.assertEqual(mock.call('example-vm-vmdisk2', 'upload-uuid', source_url=mock.ANY, shared=False,
                                   namespace=None), client.upload_artifact.call_args)

    def test_progress_is_drawn_by_tqdm(self):
        result, client, util = self._import(SMALL, disks=DISKS, progress=False)
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn('Reading disk1.vmdk', result.stderr)
        self.assertNotIn('Reading disk1.vmdk', result.stdout)

    def test_glance_not_tar(self):
        result, client, util = self._invoke(os.path.join(GLANCE, 'testserver-not-tar.ova'))
        self.assertEqual(1, result.exit_code, result.output)
        self.assertNotIn('Traceback', result.output)
        lines = self._lines(result.output)
        self.assertEqual(1, len(lines), result.output)
        self.assertTrue(lines[0].startswith(
            'The OVA cannot be read as an uncompressed tar archive, which an OVA must be: ReadError: '), lines[0])
        self.assertNothingUploaded(client, util)


class UntrustedTextTestCase(CommandTestCase):
    """Text from the OVA reaches the terminal with its control characters made visible."""

    def _licence_import(self, licence):
        envelope = ovf.parse_descriptor(_fixture(PRODUCT_AND_EULA))
        envelope.virtual_system.eulas[0].license = licence
        with mock.patch('shakenfist_client_ova.ovf.package.parse_descriptor', return_value=envelope):
            return self._import(_fixture(PRODUCT_AND_EULA))

    def assertNoControlCharacters(self, output):
        for character in output:
            if character not in '\n\t':
                self.assertFalse(ord(character) < 0x20 or 0x7f <= ord(character) <= 0x9f,
                                 'U+%04X in %r' % (ord(character), output))

    def test_printable(self):
        self.assertEqual('a\\x1b[2Jb\\x07\\x9b\\x00\\x7f\\x0d\nc\td\u00a0', ova._printable(
            'a\x1b[2Jb\x07\x9b\x00\x7f\r\nc\td\u00a0'))

    def test_printable_escapes_backslashes(self):
        # Otherwise text could pass for one of the escapes.
        self.assertEqual('a\\\\x1b[2Jb \\\\u202e', ova._printable('a\\x1b[2Jb \\u202e'))
        self.assertEqual('C:\\\\Windows\\\\System32', ova._printable('C:\\Windows\\System32'))

    def test_printable_escapes_format_characters(self):
        for character, expected in (('\u202e', '\\u202e'), ('\u202a', '\\u202a'), ('\u2066', '\\u2066'),
                                    ('\u2069', '\\u2069'), ('\u200b', '\\u200b'), ('\ufeff', '\\ufeff'),
                                    ('\U000e0001', '\\U000e0001')):
            self.assertEqual('a%sb' % expected, ova._printable('a%sb' % character), repr(character))
        # A visible character is left alone, and so is an ordinary space.
        self.assertEqual('caf\u00e9 \u65e5\u672c', ova._printable('caf\u00e9 \u65e5\u672c'))

    def test_printable_escapes_lone_surrogates(self):
        # A member name that is not valid UTF-8 is read with each bad byte as
        # a lone surrogate, which cannot be encoded to print.
        for character, expected in (('\udcff', '\\udcff'), ('\udc80', '\\udc80'), ('\ud800', '\\ud800')):
            printable = ova._printable('a%sb' % character)
            self.assertEqual('a%sb' % expected, printable, repr(character))
            printable.encode('utf-8')
        # A character outside the Basic Multilingual Plane is not a surrogate.
        self.assertEqual('\U0001f600', ova._printable('\U0001f600'))

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
        with mock.patch('shakenfist_client_ova.ovf.package.parse_descriptor', side_effect=error):
            result, client, util = self._import(_fixture(PRODUCT_AND_EULA))
        self.assertEqual(1, result.exit_code, result.output)
        self.assertNotIn('\x1b', result.output)
        self.assertNotIn('\x07', result.output)
        self.assertIn('ovf:size is "\\x1b]0;evil\\x07", which is bad', result.output)
        self.assertNothingUploaded(client, util)

    def test_member_names_are_made_visible(self):
        # XML refuses ESC in an href, but not a C1 control; a member nothing
        # references can be named anything.
        descriptor = _replace(SMALL, 'ovf:href="disk1.vmdk"', 'ovf:href="evil&#x9b;2J.vmdk"')
        result, _, _ = self._import(descriptor, disks=[('evil\x9b2J.vmdk', DISK1), ('disk2.vmdk', DISK2)],
                                    extra=[('evil\x1b[2J.txt', b'x')])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertIn('    File file1: evil\\x9b2J.vmdk\n', result.output)
        self.assertIn('    Ignored, as nothing references it: evil\\x1b[2J.txt\n', result.output)
        self.assertIn('    evil\\x9b2J.vmdk: its SHA256 digest matches the manifest\n', result.output)
        self.assertIn('evil\\x9b2J.vmdk with size 5 Bytes', result.output)
        self.assertEqual('Reading evil\\x9b2J.vmdk', self.bars[0].kwargs['desc'])
        self.assertNoControlCharacters(result.output)

    def test_member_name_that_is_not_utf8(self):
        # tarfile reads each byte of a name that is not valid UTF-8 as a lone
        # surrogate, and writes a name holding one back as that byte.
        result, _, _ = self._import(SMALL, disks=DISKS, extra=[('bad\udcff.txt', b'x')])
        self.assertEqual(0, result.exit_code, result.output)
        self.assertNotIn('Traceback', result.output)
        self.assertIn('    Ignored, as nothing references it: bad\\udcff.txt\n', result.output)


# What each OVFError subclass is raised by: a function writing, at the path it
# is given, an OVA that open_package() refuses with exactly that error.
def _described(descriptor):
    """An OVA of a descriptor that the parser refuses, with a SHA256 manifest and a member for each File."""
    return _archive(_members(descriptor))


def _synthetic(old, new, name=TWO_CONTROLLERS):
    return _described(_text(name, old, new))


def _small(descriptor=SMALL, disks=DISKS, **kwargs):
    """An OVA of the small two-disk descriptor and its disks, as _members() builds it."""
    return _archive(_members(descriptor, disks=disks), **kwargs)


RAISERS = {
    ovf.ManifestError: _archive([('x.ovf', SMALL), ('x.mf', b'this is not a manifest line\n')] + DISKS),
    ovf.UnknownAllocationUnitError: _synthetic('byte * 2^30', 'hertz * 2^30'),
    ovf.UnsupportedHardwareError: _synthetic(
        '<rasd:ResourceType>10</rasd:ResourceType>', '<rasd:ResourceType>99</rasd:ResourceType>'),
    ovf.UnparsedContentError: _described(_fixture('handwritten/unknown-ovf-attribute.ovf')),
    ovf.MalformedDescriptorError: _described(_fixture(TWO_CONTROLLERS)[:400]),
    ovf.EntityDeclarationError: _described(_fixture('handwritten/entity-declaration.ovf')),
    ovf.UnsupportedEnvelopeError: _described(_fixture('vendor/tails-202607.ovf')),
    ovf.VirtualSystemCollectionError: _described(_fixture('handwritten/virtual-system-collection.ovf')),
    ovf.UnsupportedProducerError: _described(_fixture('vendor/oracle-linux-9.8-olvm.ovf')),
    ovf.MissingContentError: _synthetic('<VirtualSystem ovf:id="example-vm">', '<VirtualSystem>'),
    ovf.InvalidValueError: _synthetic('ovf:capacity="10"', 'ovf:capacity="ten"'),
    ovf.BrokenReferenceError: _synthetic('ovf:fileRef="file1"', 'ovf:fileRef="nowhere"'),
    ovf.NotAnArchiveError: _small(compressed=True),
    ovf.PackageLayoutError: _archive(_members(SMALL, disks=DISKS) + [('y.ovf', SMALL)]),
    ovf.FileReferenceError: _small(_replace(SMALL, FILE1, 'ovf:href="/disk1.vmdk" ovf:size="5"')),
    ovf.ChunkedFileError: _small(_replace(SMALL, FILE1, FILE1 + ' ovf:chunkSize="2"')),
    ovf.MissingMemberError: _small(disks=DISKS[:1]),
    ovf.MemberTypeError: _small(disks=DISKS[:1] + [synthetic.symlink('disk2.vmdk', 'disk1.vmdk')]),
    ovf.FileSizeError: _small(disks=[('disk1.vmdk', b'disk'), ('disk2.vmdk', DISK2)]),
    ovf.CompressedFileError: _small(_replace(SMALL, FILE1, FILE1 + ' ovf:compression="gzip"')),
    ovf.UnlistedFileError: _archive(
        [('x.ovf', SMALL), ('x.mf', _manifest([('x.ovf', SMALL), ('disk1.vmdk', DISK1)]))] + DISKS),
    ovf.DigestMismatchError: _archive(
        [('x.ovf', SMALL), ('x.mf', _manifest([('x.ovf', SMALL + b'\n')] + DISKS))] + DISKS),
    ovf.DeltaDiskError: _small(_replace(SMALL, '<Disk ovf:diskId="vmdisk2"',
                                        '<Disk ovf:diskId="vmdisk2" ovf:parentRef="vmdisk1"')),
}


class ErrorsTestCase(CommandTestCase):
    def _refusal(self, raiser):
        """The OVFError open_package() raises for the OVA raiser writes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'x.ova')
            raiser(path)
            try:
                ovf.open_package(path).close()
            except ovf.OVFError as e:
                return e
        self.fail('nothing was raised')

    def test_every_error_has_a_raiser(self):
        subclasses = set()
        pending = [ovf.OVFError]
        while pending:
            for subclass in pending.pop().__subclasses__():
                subclasses.add(subclass)
                pending.append(subclass)
        self.assertEqual(subclasses, set(RAISERS))

    def test_every_error_raises_its_error(self):
        for error, raiser in RAISERS.items():
            self.assertIs(error, type(self._refusal(raiser)), error.__name__)

    def test_every_error_is_a_line_and_an_exit(self):
        for error, raiser in sorted(RAISERS.items(), key=lambda item: item[0].__name__):
            if error is ovf.UnparsedContentError:
                continue
            result, client, util = self._run(raiser)
            self.assertEqual(1, result.exit_code, '%s: %s' % (error.__name__, result.output))
            self.assertNotIn('Traceback', result.output)
            self.assertNotIn('VM description', result.output)
            lines = self._lines(result.output)
            self.assertEqual(1, len(lines), '%s: %s' % (error.__name__, result.output))
            self.assertEqual(str(self._refusal(raiser)), lines[0])
            self.assertNothingUploaded(client, util)

    def test_unparsed_content_names_each_path_on_its_own_line(self):
        result, client, util = self._run(RAISERS[ovf.UnparsedContentError])
        self.assertEqual(1, result.exit_code, result.output)
        self.assertNotIn('Traceback', result.output)
        lines = self._lines(result.output)
        self.assertEqual(ovf.descriptor.UNPARSED_HEADING, lines[0])
        self.assertEqual(['    Envelope/VirtualSystem@ovf:exampleUnknownAttribute'], lines[1:])
        self.assertNothingUploaded(client, util)
