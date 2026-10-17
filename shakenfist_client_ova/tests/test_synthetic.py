import os
import tarfile
import tempfile

import testtools

from shakenfist_client_ova.tests import synthetic


class BuildTestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        self.path = os.path.join(tmpdir.name, 'x.ova')

    def _members(self, members, **kwargs):
        """Build an archive of members and read back each member's TarInfo, in order."""
        self.assertEqual(self.path, synthetic.build(self.path, members, **kwargs))
        with tarfile.open(self.path, 'r:') as archive:
            return archive.getmembers()

    def _read(self, name):
        with tarfile.open(self.path, 'r:') as archive:
            with archive.extractfile(name) as f:
                return f.read()

    def test_regular_files(self):
        infos = self._members([('x.ovf', b'descriptor'), synthetic.regular('disk1.vmdk', b'disk'),
                               ('empty', b'')])
        self.assertEqual(['x.ovf', 'disk1.vmdk', 'empty'], [info.name for info in infos])
        self.assertTrue(all(info.isfile() for info in infos))
        self.assertEqual([10, 4, 0], [info.size for info in infos])
        self.assertEqual(b'descriptor', self._read('x.ovf'))
        self.assertEqual(b'disk', self._read('disk1.vmdk'))

    def test_symbolic_link(self):
        info, = self._members([synthetic.symlink('disk1.vmdk', '../elsewhere.vmdk')])
        self.assertTrue(info.issym())
        self.assertFalse(info.isfile())
        self.assertEqual('../elsewhere.vmdk', info.linkname)

    def test_hard_link(self):
        infos = self._members([('real.vmdk', b'disk'), synthetic.hardlink('disk1.vmdk', 'real.vmdk')])
        self.assertTrue(infos[1].islnk())
        self.assertFalse(infos[1].isfile())
        self.assertEqual('real.vmdk', infos[1].linkname)
        # Reading a hard link reads its target, which is why the archive checks refuse one.
        self.assertEqual(b'disk', self._read('disk1.vmdk'))

    def test_hard_link_to_nothing(self):
        info, = self._members([synthetic.hardlink('disk1.vmdk', 'absent.vmdk')])
        self.assertTrue(info.islnk())
        self.assertEqual('absent.vmdk', info.linkname)

    def test_directory(self):
        infos = self._members([synthetic.directory('disks'), ('disks/disk1.vmdk', b'disk')])
        self.assertTrue(infos[0].isdir())
        self.assertEqual(['disks', 'disks/disk1.vmdk'], [info.name for info in infos])

    def test_fifo(self):
        info, = self._members([synthetic.fifo('disk1.vmdk')])
        self.assertTrue(info.isfifo())
        self.assertFalse(info.isfile())

    def test_device(self):
        info, = self._members([synthetic.device('disk1.vmdk')])
        self.assertTrue(info.ischr())
        self.assertTrue(info.isdev())
        self.assertFalse(info.isfile())

    def test_names_are_kept_as_given(self):
        names = ['./x.ovf', 'x.ovf', './disks/disk1.vmdk', 'evil\x1b[2J.vmdk', 'café.vmdk']
        infos = self._members([(name, b'') for name in names])
        self.assertEqual(names, [info.name for info in infos])

    def test_duplicates_are_kept_in_order(self):
        infos = self._members([('disk1.vmdk', b'first'), ('x.ovf', b''), ('disk1.vmdk', b'second!')])
        self.assertEqual(['disk1.vmdk', 'x.ovf', 'disk1.vmdk'], [info.name for info in infos])
        self.assertEqual([5, 0, 7], [info.size for info in infos])

    def test_same_members_build_the_same_bytes(self):
        members = [('x.ovf', b'descriptor'), synthetic.symlink('a', 'b'), synthetic.directory('d')]
        synthetic.build(self.path, members)
        with open(self.path, 'rb') as f:
            first = f.read()
        synthetic.build(self.path, members)
        with open(self.path, 'rb') as f:
            self.assertEqual(first, f.read())

    def test_plain_tar(self):
        synthetic.build(self.path, [('x.ovf', b'descriptor')])
        with open(self.path, 'rb') as f:
            self.assertNotEqual(b'\x1f\x8b', f.read(2))

    def test_compressed(self):
        synthetic.build(self.path, [('x.ovf', b'descriptor')], compressed=True)
        with open(self.path, 'rb') as f:
            self.assertEqual(b'\x1f\x8b', f.read(2))
        self.assertRaises(tarfile.ReadError, tarfile.open, self.path, 'r:')
        with tarfile.open(self.path, 'r:gz') as archive:
            self.assertEqual(['x.ovf'], archive.getnames())
            with archive.extractfile('x.ovf') as f:
                self.assertEqual(b'descriptor', f.read())

    def _check_truncated(self, mode, length):
        with tarfile.open(self.path, mode) as archive:
            # Both headers are there, but the disk's data stops half way, which
            # a read of the disk finds, and so does listing past it.
            ovf, disk = archive.next(), archive.next()
            self.assertEqual(['x.ovf', 'disk1.vmdk'], [ovf.name, disk.name])
            self.assertEqual(length, disk.size)
            with archive.extractfile(disk) as f:
                self.assertRaises(tarfile.ReadError, f.read)
            self.assertRaises(tarfile.ReadError, archive.next)
        with tarfile.open(self.path, mode) as archive:
            self.assertRaises(tarfile.ReadError, archive.getmembers)

    def test_truncated(self):
        disk = b'0123456789' * 200
        synthetic.build(self.path, [('x.ovf', b'descriptor'), ('disk1.vmdk', disk)], truncated=True)
        self.assertEqual(3 * 512 + len(disk) // 2, os.path.getsize(self.path))
        self._check_truncated('r:', len(disk))

    def test_truncated_and_compressed(self):
        disk = b'0123456789' * 200
        synthetic.build(self.path, [('x.ovf', b'descriptor'), ('disk1.vmdk', disk)], compressed=True, truncated=True)
        self._check_truncated('r:gz', len(disk))

    def test_truncated_needs_a_regular_last_member(self):
        for members in ([], [('x.ovf', b'descriptor'), synthetic.directory('d')], [('disk1.vmdk', b'd')]):
            self.assertRaises(ValueError, synthetic.build, self.path, members, truncated=True)
