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

    def test_hardware_summary_shows_both_disk_drives(self):
        envelope = ovf.parse_descriptor(_fixture('handwritten/two-controllers.ovf'))
        lines = _hardware_summary(envelope.virtual_system.hardware[0])
        self.assertEqual(
            ['    Disk drive: Hard disk 1 at address 0 on controller 3',
             '    Disk drive: Hard disk 2 at address 0 on controller 6'],
            [line for line in lines if line.startswith('    Disk drive:')])


class ImportCommandTestCase(testtools.TestCase):
    def _import(self, descriptor):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'x.ova')
            with tarfile.open(path, 'w') as archive:
                info = tarfile.TarInfo('x.ovf')
                info.size = len(descriptor)
                archive.addfile(info, io.BytesIO(descriptor))

            with mock.patch('shakenfist_client_ova.apiclient.Client') as client_class, \
                    mock.patch('shakenfist_client_ova.util') as util:
                result = CliRunner().invoke(ova.ova, ['import', path], obj={})
        return result, client_class.return_value, util

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
        client.check_capability.assert_not_called()
        client.blob_artifact.assert_not_called()
        util.checksum_with_progress_from_file_like_object.assert_not_called()
        util.upload_artifact_with_progress_file_like_object.assert_not_called()
