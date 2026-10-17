"""The package reader, on OVAs built by tests/synthetic.py and on Glance's.

Every archive here is built in a temporary directory from a list of members,
most of them around the hand-written two-controllers.ovf. DESCRIPTOR is that
descriptor with its files' ovf:size cut to five bytes, so that the disks are
small; the one test of the descriptor as it is uses disks of its full size.
"""

import errno
import hashlib
import io
import os
import tarfile
import tempfile
from unittest import mock

import testtools

from shakenfist_client_ova import ovf
from shakenfist_client_ova.ovf import package as package_module
from shakenfist_client_ova.tests import synthetic


FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')
HANDWRITTEN = os.path.join(FIXTURES, 'ovf', 'handwritten')
GLANCE = os.path.join(FIXTURES, 'ova', 'imported', 'glance')

MIB = 1024 * 1024


def _fixture(name):
    with open(os.path.join(HANDWRITTEN, name), 'rb') as f:
        return f.read()


def _replace(data, old, new):
    """Bytes with every occurrence of the text old replaced by new, which must occur."""
    text = data.decode()
    assert old in text, old
    return text.replace(old, new).encode()


TWO_CONTROLLERS = _fixture('two-controllers.ovf')
DESCRIPTOR = _replace(TWO_CONTROLLERS, 'ovf:size="1048576"', 'ovf:size="5"')
DISK1 = b'disk1'
DISK2 = b'disk2'
FILE1 = 'ovf:href="disk1.vmdk" ovf:size="5"'
FILE2 = 'ovf:href="disk2.vmdk" ovf:size="5"'


def _file1(attributes, descriptor=DESCRIPTOR):
    """The descriptor with the first File's ovf:href and ovf:size replaced by attributes."""
    return _replace(descriptor, FILE1, attributes)


def _href(href):
    return _file1('ovf:href="%s" ovf:size="5"' % href)


def _add_file(attributes, descriptor=DESCRIPTOR):
    """The descriptor with a third File, file3, that no Disk names."""
    return _replace(descriptor, FILE2 + '/>', FILE2 + '/>\n    <File ovf:id="file3" %s/>' % attributes)


def _digest(algorithm, data):
    return hashlib.new(algorithm.lower(), data).hexdigest()


def _manifest(members, algorithm='SHA256'):
    """A manifest giving each member its digest in the algorithm, which is written as given.

    members are (name, data) pairs or synthetic.Members, whose data is empty
    unless they are regular files.
    """
    pairs = [(member.name, member.data) if isinstance(member, synthetic.Member) else member for member in members]
    return ''.join('%s(%s)= %s\n' % (algorithm, name, _digest(algorithm, data)) for name, data in pairs).encode()


def _members(descriptor=DESCRIPTOR, disks=None, algorithm='SHA256'):
    """x.ovf, then x.mf giving the descriptor's and each disk's digest unless algorithm is None, then the disks.

    disks are (name, data) pairs or synthetic.Members, by default both of DESCRIPTOR's.
    """
    if disks is None:
        disks = [('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)]
    members = [('x.ovf', descriptor)]
    if algorithm is not None:
        members.append(('x.mf', _manifest(members + disks, algorithm)))
    return members + disks


class PackageTestCase(testtools.TestCase):
    def setUp(self):
        super().setUp()
        tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(tmpdir.cleanup)
        self.path = os.path.join(tmpdir.name, 'x.ova')

    def _build(self, members, **kwargs):
        return synthetic.build(self.path, members, **kwargs)

    def _open(self, members, **kwargs):
        """Build an archive of members and open it, closing it when the test ends."""
        self._build(members, **kwargs)
        package = ovf.open_package(self.path)
        self.addCleanup(package.close)
        return package

    def _refused(self, error, members, **kwargs):
        """Build an archive of members, and check that opening it raises exactly error, which is returned."""
        self._build(members, **kwargs)
        try:
            package = ovf.open_package(self.path)
        except ovf.OVFError as e:
            self.assertIs(error, type(e), str(e))
            self.assertNotIn('\n', str(e))
            return e
        package.close()
        self.fail('%s was not raised' % error.__name__)


class PassingTestCase(PackageTestCase):
    def test_two_disks_with_a_sha256_manifest(self):
        # Two disks, as vulnhub-blogger has, in ovftool's order: the
        # descriptor, the manifest, then the disks, at their full size.
        disk1 = b'1' * MIB
        disk2 = b'2' * MIB
        manifest = _manifest([('x.ovf', TWO_CONTROLLERS), ('disk1.vmdk', disk1), ('disk2.vmdk', disk2)])
        package = self._open([('x.ovf', TWO_CONTROLLERS), ('x.mf', manifest), ('disk1.vmdk', disk1),
                              ('disk2.vmdk', disk2)])

        envelope = ovf.parse_descriptor(TWO_CONTROLLERS)
        self.assertEqual('x.ovf', package.descriptor_member)
        self.assertEqual('x.mf', package.manifest_member)
        self.assertIsNone(package.certificate_member)
        self.assertEqual(envelope, package.envelope)
        self.assertEqual(ovf.parse_manifest(manifest), package.manifest)
        self.assertEqual(['sha256'] * 3, [entry.algorithm for entry in package.manifest.entries])
        self.assertEqual({'file1': 'disk1.vmdk', 'file2': 'disk2.vmdk'}, package.file_members)
        self.assertEqual(
            [ovf.Upload(disk=envelope.disks[0], file=envelope.files[0], member='disk1.vmdk'),
             ovf.Upload(disk=envelope.disks[1], file=envelope.files[1], member='disk2.vmdk')],
            package.uploads)
        self.assertEqual(['vmdisk1', 'vmdisk2'], [upload.disk.disk_id for upload in package.uploads])
        self.assertEqual(['file1', 'file2'], [upload.file.id for upload in package.uploads])
        self.assertEqual([], package.blank_disks)
        self.assertEqual([], package.unused_files)
        self.assertEqual([], package.unreferenced_members)
        self.assertEqual([], package.unreferenced_entries)
        self.assertFalse(package.manifest_name_differs)
        self.assertEqual(ovf.ManifestEntry(name='disk2.vmdk', algorithm='sha256', digest=_digest('sha256', disk2)),
                         package.manifest_entry('disk2.vmdk'))
        self.assertIsNone(package.manifest_entry('absent.vmdk'))

        for upload, data in zip(package.uploads, (disk1, disk2)):
            digests = package.digests(upload.member, ['sha256', 'sha512'])
            self.assertEqual({'sha256': _digest('sha256', data), 'sha512': _digest('sha512', data)}, digests)
            package.check_digest(upload.member, digests)
            with package.open_member(upload.member) as f:
                self.assertTrue(f.seekable())
                self.assertEqual(data, f.read())
                f.seek(MIB - 3)
                self.assertEqual(data[-3:], f.read())

    def test_no_manifest(self):
        package = self._open(_members(algorithm=None))
        self.assertIsNone(package.manifest_member)
        self.assertIsNone(package.manifest)
        self.assertFalse(package.manifest_name_differs)
        self.assertEqual([], package.unreferenced_entries)
        self.assertIsNone(package.manifest_entry('disk1.vmdk'))
        self.assertEqual(['disk1.vmdk', 'disk2.vmdk'], [upload.member for upload in package.uploads])
        digests = package.digests('disk1.vmdk', ['sha512'])
        self.assertEqual({'sha512': _digest('sha512', DISK1)}, digests)
        self.assertRaises(ValueError, package.check_digest, 'disk1.vmdk', digests)

    def test_each_algorithm_in_either_case(self):
        for algorithm in ('SHA1', 'sha1', 'SHA256', 'SHA512', 'Sha512'):
            package = self._open(_members(algorithm=algorithm))
            self.assertEqual([algorithm.lower()] * 3, [entry.algorithm for entry in package.manifest.entries])
            for upload in package.uploads:
                package.check_digest(upload.member, package.digests(upload.member, [algorithm.lower()]))

    def test_upper_case_digests_match(self):
        members = [('x.ovf', DESCRIPTOR), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)]
        manifest = _manifest(members).decode()
        for _, data in members:
            digest = _digest('sha256', data)
            manifest = manifest.replace(digest, digest.upper())
        package = self._open(members + [('x.mf', manifest.encode())])
        self.assertEqual(_digest('sha256', DISK1).upper(), package.manifest_entry('disk1.vmdk').digest)
        package.check_digest('disk1.vmdk', package.digests('disk1.vmdk', ['sha256']))

    def test_manifest_stored_last(self):
        # VirtualBox's order: the manifest after the disks.
        members = [('x.ovf', DESCRIPTOR), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)]
        package = self._open(members + [('x.mf', _manifest(members))])
        self.assertEqual('x.mf', package.manifest_member)
        self.assertEqual(['disk1.vmdk', 'disk2.vmdk'], [upload.member for upload in package.uploads])

    def test_certificate(self):
        members = _members()
        package = self._open(members[:2] + [('x.cert', b'not checked')] + members[2:])
        self.assertEqual('x.cert', package.certificate_member)
        self.assertEqual([], package.unreferenced_members)

    def test_members_with_a_dot_slash(self):
        members = [('x.ovf', DESCRIPTOR), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)]
        manifest = _manifest(members)
        package = self._open([synthetic.directory('./')] + [('./' + name, data) for name, data in members]
                             + [('./x.mf', manifest)])
        self.assertEqual('x.ovf', package.descriptor_member)
        self.assertEqual('x.mf', package.manifest_member)
        self.assertEqual({'file1': 'disk1.vmdk', 'file2': 'disk2.vmdk'}, package.file_members)
        self.assertEqual([], package.unreferenced_members)
        package.check_digest('disk1.vmdk', package.digests('disk1.vmdk', ['sha256']))
        with package.open_member('disk2.vmdk') as f:
            self.assertEqual(DISK2, f.read())

    def test_href_with_a_dot_slash(self):
        package = self._open(_members(descriptor=_href('./disk1.vmdk')))
        self.assertEqual('disk1.vmdk', package.file_members['file1'])
        self.assertEqual('disk1.vmdk', package.uploads[0].member)

    def test_href_in_a_subdirectory(self):
        package = self._open(_members(descriptor=_href('disks/disk1.vmdk'), disks=[
            ('disk2.vmdk', DISK2), synthetic.directory('disks'), ('disks/disk1.vmdk', DISK1)]))
        self.assertEqual('disks/disk1.vmdk', package.file_members['file1'])
        self.assertEqual('disks/disk1.vmdk', package.uploads[0].member)
        # The directory is left out of the members nothing references.
        self.assertEqual([], package.unreferenced_members)

    def test_href_is_not_percent_decoded(self):
        package = self._open(_members(descriptor=_href('disk%31.vmdk'), disks=[
            ('disk%31.vmdk', DISK1), ('disk2.vmdk', DISK2)]))
        self.assertEqual('disk%31.vmdk', package.file_members['file1'])

    def test_file_no_disk_uses(self):
        descriptor = _add_file('ovf:href="tools.iso"')
        package = self._open(_members(descriptor=descriptor, disks=[
            ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2), ('tools.iso', b'an iso')]))
        self.assertEqual([ovf.File(id='file3', href='tools.iso')], package.unused_files)
        self.assertEqual('tools.iso', package.file_members['file3'])
        self.assertEqual(['disk1.vmdk', 'disk2.vmdk'], [upload.member for upload in package.uploads])
        self.assertEqual([], package.unreferenced_members)

    def test_disk_with_no_file(self):
        descriptor = _replace(DESCRIPTOR, '</DiskSection>', '<Disk ovf:diskId="vmdisk3" ovf:capacity="1" '
                              'ovf:capacityAllocationUnits="byte * 2^30"/></DiskSection>')
        package = self._open(_members(descriptor=descriptor))
        self.assertEqual(['vmdisk3'], [disk.disk_id for disk in package.blank_disks])
        self.assertEqual(['vmdisk1', 'vmdisk2'], [upload.disk.disk_id for upload in package.uploads])

    def test_identity_compression(self):
        package = self._open(_members(descriptor=_file1(FILE1 + ' ovf:compression="identity"')))
        self.assertEqual('identity', package.uploads[0].file.compression)

    def test_no_size(self):
        package = self._open(_members(descriptor=_file1('ovf:href="disk1.vmdk"'), disks=[
            ('disk1.vmdk', b'any size at all'), ('disk2.vmdk', DISK2)]))
        self.assertIsNone(package.uploads[0].file.size)

    def test_unreferenced_members(self):
        members = _members()
        package = self._open(members[:2] + [('README.txt', b'read me'), synthetic.directory('extras'),
                                            synthetic.symlink('link', 'disk1.vmdk'), ('sub/other.ovf', b'')]
                             + members[2:] + [('sub/x.mf', b''), synthetic.fifo('pipe')])
        # A .ovf or .mf member in a subdirectory is an ordinary file.
        self.assertEqual('x.ovf', package.descriptor_member)
        self.assertEqual('x.mf', package.manifest_member)
        self.assertEqual(['README.txt', 'link', 'sub/other.ovf', 'sub/x.mf', 'pipe'], package.unreferenced_members)

    def test_manifest_in_a_subdirectory_is_not_the_manifest(self):
        members = _members(algorithm=None)
        package = self._open(members + [('sub/x.mf', _manifest(members))])
        self.assertIsNone(package.manifest_member)
        self.assertEqual(['sub/x.mf'], package.unreferenced_members)

    def test_unreferenced_entries(self):
        members = [('x.ovf', DESCRIPTOR), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)]
        extra = [('README.txt', b'read me'), ('x.cert', b'cert'), ('absent.vmdk', b'')]
        manifest = _manifest(extra[:1] + members + extra[1:])
        package = self._open(members + [('x.mf', manifest), ('README.txt', b'read me'), ('x.cert', b'cert')])
        self.assertEqual(['README.txt', 'x.cert', 'absent.vmdk'],
                         [entry.name for entry in package.unreferenced_entries])
        self.assertEqual(['README.txt'], package.unreferenced_members)

    def test_manifest_named_differently(self):
        members = [('x.ovf', DESCRIPTOR), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)]
        package = self._open(members + [('other.mf', _manifest(members))])
        self.assertEqual('other.mf', package.manifest_member)
        self.assertTrue(package.manifest_name_differs)


class LayoutTestCase(PackageTestCase):
    def test_two_members_with_one_name(self):
        e = self._refused(ovf.PackageLayoutError, _members() + [('disk1.vmdk', b'other')])
        self.assertEqual('The archive holds two members named "disk1.vmdk", and DSP0243 allows each member only once',
                         str(e))

    def test_two_members_with_one_name_once_dot_slash_is_removed(self):
        e = self._refused(ovf.PackageLayoutError, _members() + [('./disk1.vmdk', DISK1)])
        self.assertEqual('The archive holds two members named "disk1.vmdk" (written "disk1.vmdk" and "./disk1.vmdk"), '
                         'and DSP0243 allows each member only once', str(e))

    def test_descriptor_twice_once_dot_slash_is_removed(self):
        self._refused(ovf.PackageLayoutError, [('./x.ovf', DESCRIPTOR)] + _members())

    def test_directory_and_file_with_one_name(self):
        self._refused(ovf.PackageLayoutError, _members() + [synthetic.directory('disks'), ('disks', b'')])

    def test_only_one_dot_slash_is_removed(self):
        # ././x.ovf is ./x.ovf once one ./ is removed: in a subdirectory, so no descriptor.
        e = self._refused(ovf.PackageLayoutError, [('././x.ovf', DESCRIPTOR), ('disk1.vmdk', DISK1)])
        self.assertIn('holds no descriptor', str(e))

    def test_no_descriptor(self):
        e = self._refused(ovf.PackageLayoutError, [('disk1.vmdk', DISK1), ('sub/x.ovf', DESCRIPTOR)])
        self.assertEqual('The archive holds no descriptor: no top-level member\'s name ends in .ovf', str(e))

    def test_empty_archive(self):
        self._refused(ovf.PackageLayoutError, [])

    def test_two_descriptors(self):
        e = self._refused(ovf.PackageLayoutError, _members() + [('y.ovf', DESCRIPTOR)])
        self.assertEqual('The archive holds more than one descriptor: "x.ovf", "y.ovf"', str(e))

    def test_two_manifests(self):
        e = self._refused(ovf.PackageLayoutError, _members() + [('y.mf', b'not even read')])
        self.assertEqual('The archive holds more than one manifest: "x.mf", "y.mf"', str(e))

    def test_two_certificates(self):
        e = self._refused(ovf.PackageLayoutError, _members() + [('x.cert', b''), ('y.cert', b'')])
        self.assertEqual('The archive holds more than one certificate: "x.cert", "y.cert"', str(e))

    def test_certificate_without_a_manifest(self):
        e = self._refused(ovf.PackageLayoutError, _members(algorithm=None) + [('x.cert', b'')])
        self.assertEqual('The archive holds the certificate "x.cert" but no manifest, and a certificate signs the '
                         'manifest', str(e))

    def test_descriptor_manifest_and_certificate_must_be_regular_files(self):
        members = _members()
        for what, name in (('descriptor', 'x.ovf'), ('manifest', 'x.mf'), ('certificate', 'x.cert')):
            for kind, member in (('a symbolic link', synthetic.symlink(name, 'elsewhere')),
                                 ('a hard link', synthetic.hardlink(name, 'disk1.vmdk')),
                                 ('a directory', synthetic.directory(name)),
                                 ('a FIFO', synthetic.fifo(name)),
                                 ('a device', synthetic.device(name))):
                kept = [m for m in members if m[0] != name]
                e = self._refused(ovf.PackageLayoutError, [member] + kept)
                self.assertEqual('The %s "%s" is %s, not a regular file' % (what, name, kind), str(e))

    def test_descriptor_at_the_limit(self):
        descriptor = DESCRIPTOR + b' ' * (package_module.MAX_DESCRIPTOR_SIZE - len(DESCRIPTOR))
        self.assertEqual(16 * MIB, len(descriptor))
        package = self._open(_members(descriptor=descriptor))
        self.assertEqual('x.ovf', package.descriptor_member)

    def test_descriptor_over_the_limit_is_not_read(self):
        # Over the limit, and not XML, which would be refused if it were read.
        descriptor = DESCRIPTOR + b'x' * (package_module.MAX_DESCRIPTOR_SIZE + 1 - len(DESCRIPTOR))
        e = self._refused(ovf.PackageLayoutError, _members(descriptor=descriptor))
        self.assertEqual('The descriptor "x.ovf" is 16777217 bytes, more than the 16777216 bytes the parser reads',
                         str(e))

    def test_manifest_at_the_limit(self):
        members = _members()
        manifest = members[1][1] + b'\n' * (package_module.MAX_MANIFEST_SIZE - len(members[1][1]))
        self.assertEqual(MIB, len(manifest))
        package = self._open(members[:1] + [('x.mf', manifest)] + members[2:])
        self.assertEqual(3, len(package.manifest.entries))

    def test_manifest_over_the_limit_is_not_read(self):
        members = _members()
        manifest = b'x' * (package_module.MAX_MANIFEST_SIZE + 1)
        e = self._refused(ovf.PackageLayoutError, members[:1] + [('x.mf', manifest)] + members[2:])
        self.assertEqual('The manifest "x.mf" is 1048577 bytes, more than the 1048576 bytes the parser reads', str(e))

    def test_layout_is_checked_before_anything_is_read(self):
        # An unparseable manifest and a malformed descriptor are never read.
        self._refused(ovf.PackageLayoutError, [('x.ovf', b'<not'), ('x.mf', b'not a manifest'), ('y.mf', b'')])
        self._refused(ovf.PackageLayoutError, [('x.ovf', b'<not'), ('x.mf', b'not a manifest'),
                                               ('disk1.vmdk', b''), ('disk1.vmdk', b'')])


class ArchiveTestCase(PackageTestCase):
    def assertNotAnArchive(self, e, cause):
        self.assertIn('cannot be read as an uncompressed tar archive, which an OVA must be', str(e))
        self.assertIsInstance(e.__cause__, cause)
        self.assertEqual('NotAnArchiveError(%s)' % cause.__name__, ovf.outcome_name(e))

    def test_gzip_compressed_tar(self):
        e = self._refused(ovf.NotAnArchiveError, _members(), compressed=True)
        self.assertNotAnArchive(e, tarfile.ReadError)

    def test_truncated_tar(self):
        e = self._refused(ovf.NotAnArchiveError, _members(disks=[('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)]),
                          truncated=True)
        self.assertNotAnArchive(e, tarfile.ReadError)

    def test_not_a_tar(self):
        with open(self.path, 'wb') as f:
            f.write(b'This is not a tar archive. ' * 100)
        e = self.assertRaises(ovf.NotAnArchiveError, ovf.open_package, self.path)
        self.assertNotAnArchive(e, tarfile.ReadError)

    def test_empty_file(self):
        open(self.path, 'wb').close()
        e = self.assertRaises(ovf.NotAnArchiveError, ovf.open_package, self.path)
        self.assertNotAnArchive(e, tarfile.ReadError)

    def test_no_file(self):
        e = self.assertRaises(ovf.NotAnArchiveError, ovf.open_package, self.path)
        self.assertNotAnArchive(e, FileNotFoundError)

    def test_short_read_while_hashing(self):
        # The archive is complete when it is opened, and loses its end before
        # the disk is read, as a short read finds.
        disk = b'0123456789' * 300000
        descriptor = _file1('ovf:href="disk1.vmdk"')
        package = self._open(_members(descriptor=descriptor, algorithm=None, disks=[
            ('disk2.vmdk', DISK2), ('disk1.vmdk', disk)]))
        os.truncate(self.path, os.path.getsize(self.path) // 2)
        e = self.assertRaises(ovf.NotAnArchiveError, package.digests, 'disk1.vmdk', ['sha256'])
        self.assertTrue(str(e).startswith('Could not read "disk1.vmdk" from the OVA: ReadError: '), str(e))
        self.assertIsInstance(e.__cause__, tarfile.ReadError)
        self.assertEqual('NotAnArchiveError(ReadError)', ovf.outcome_name(e))

    def test_read_that_ends_early_while_hashing(self):
        package = self._open(_members())
        with mock.patch.object(tarfile.TarFile, 'extractfile', return_value=io.BytesIO(b'dis')):
            e = self.assertRaises(ovf.NotAnArchiveError, package.digests, 'disk1.vmdk', ['sha256'])
        self.assertEqual('The OVA ends part way through "disk1.vmdk": 3 of its 5 bytes could be read', str(e))
        self.assertIsNone(e.__cause__)

    def test_read_that_ends_early_while_opening(self):
        self._build(_members(algorithm=None))
        with mock.patch.object(tarfile.TarFile, 'extractfile', return_value=io.BytesIO(b'')):
            e = self.assertRaises(ovf.NotAnArchiveError, ovf.open_package, self.path)
        self.assertEqual('The OVA ends part way through "x.ovf": 0 of its %d bytes could be read' % len(DESCRIPTOR),
                         str(e))

    def test_input_output_error_while_hashing(self):
        class Failing(io.RawIOBase):
            def readable(self):
                return True

            def readinto(self, buffer):
                raise OSError(errno.EIO, 'Input/output error')

        package = self._open(_members())
        with mock.patch.object(tarfile.TarFile, 'extractfile', return_value=Failing()):
            e = self.assertRaises(ovf.NotAnArchiveError, package.digests, 'disk1.vmdk', ['sha256'])
        self.assertEqual('Could not read "disk1.vmdk" from the OVA: OSError: [Errno 5] Input/output error', str(e))
        self.assertEqual('NotAnArchiveError(OSError)', ovf.outcome_name(e))

    def test_progress_errors_are_not_archive_errors(self):
        # Only tarfile's calls are wrapped: an error of the caller's own is its own.
        def progress(length):
            raise BrokenPipeError(errno.EPIPE, 'Broken pipe')

        package = self._open(_members())
        self.assertRaises(BrokenPipeError, package.digests, 'disk1.vmdk', ['sha256'], progress)


class DescriptorDigestTestCase(PackageTestCase):
    def _manifest_members(self, descriptor, manifest):
        return [('x.ovf', descriptor), ('x.mf', manifest), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)]

    def test_descriptor_digest_differs(self):
        manifest = _manifest([('x.ovf', b'another descriptor'), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)])
        e = self._refused(ovf.DigestMismatchError, self._manifest_members(DESCRIPTOR, manifest))
        self.assertEqual('The SHA256 digest of "x.ovf" is %s, but the manifest "x.mf" gives %s' % (
            _digest('sha256', DESCRIPTOR), _digest('sha256', b'another descriptor')), str(e))

    def test_descriptor_is_checked_before_it_is_parsed(self):
        manifest = _manifest([('x.ovf', b'<well-formed/>'), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)])
        self._refused(ovf.DigestMismatchError, self._manifest_members(b'<not well-formed', manifest))

    def test_matching_malformed_descriptor_is_parsed(self):
        descriptor = b'<not well-formed'
        manifest = _manifest([('x.ovf', descriptor), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)])
        self._refused(ovf.MalformedDescriptorError, self._manifest_members(descriptor, manifest))

    def test_manifest_without_the_descriptor(self):
        manifest = _manifest([('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)])
        e = self._refused(ovf.UnlistedFileError, self._manifest_members(b'<not well-formed', manifest))
        self.assertEqual('The manifest "x.mf" has no entry for the descriptor "x.ovf"', str(e))

    def test_manifest_listing_one_file_twice(self):
        manifest = _manifest([('x.ovf', DESCRIPTOR), ('disk1.vmdk', DISK1), ('disk1.vmdk', DISK1),
                              ('disk2.vmdk', DISK2)])
        e = self._refused(ovf.ManifestError, self._manifest_members(DESCRIPTOR, manifest))
        self.assertIn('repeats "disk1.vmdk"', str(e))

    def test_manifest_that_does_not_parse(self):
        self._refused(ovf.ManifestError, self._manifest_members(DESCRIPTOR, b'not a manifest line\n'))


class ReferenceTestCase(PackageTestCase):
    def _reference_refused(self, href):
        return self._refused(ovf.FileReferenceError, _members(descriptor=_href(href)))

    def test_empty_href(self):
        for href in ('', './'):
            e = self._reference_refused(href)
            self.assertEqual('The File "file1" has the ovf:href "%s", which names no member' % href, str(e))

    def test_url(self):
        for href in ('https://example.com/disk1.vmdk', 'file:///disk1.vmdk', 'file:disk1.vmdk', 'x+y.z-1:disk1.vmdk',
                     'HTTP://example.com/disk1.vmdk'):
            e = self._reference_refused(href)
            self.assertEqual('The File "file1" has the ovf:href "%s", which has a URL scheme: an href names a member '
                             'of the archive' % href, str(e))

    def test_absolute_path(self):
        e = self._reference_refused('/disk1.vmdk')
        self.assertEqual('The File "file1" has the ovf:href "/disk1.vmdk", which starts with /: an href names a '
                         'member of the archive', str(e))

    def test_dot_segments(self):
        for href in ('../disk1.vmdk', 'disks/../disk1.vmdk', 'disks/./disk1.vmdk', '././disk1.vmdk', '.', '..',
                     'disks/..', './../disk1.vmdk'):
            e = self._reference_refused(href)
            self.assertEqual('The File "file1" has the ovf:href "%s", which has a . or .. segment, so names no member '
                             'of the archive' % href, str(e))

    def test_names_that_only_look_like_dot_segments(self):
        disks = [('.disk1.vmdk', DISK1), ('disk2.vmdk', DISK2), ('...', b'dots!'), ('a..b', b'two')]
        package = self._open(_members(descriptor=_add_file('ovf:href="a..b"', _href('.disk1.vmdk')), disks=disks))
        self.assertEqual({'file1': '.disk1.vmdk', 'file2': 'disk2.vmdk', 'file3': 'a..b'}, package.file_members)
        package = self._open(_members(descriptor=_href('...'), disks=disks))
        self.assertEqual('...', package.file_members['file1'])

    def test_two_files_with_one_href(self):
        for href in ('disk2.vmdk', './disk2.vmdk'):
            e = self._reference_refused(href)
            self.assertEqual('The File "file2" has the ovf:href "disk2.vmdk", naming the member "disk2.vmdk", which '
                             'the File "file1" names too', str(e))

    def test_href_naming_the_descriptor_manifest_or_certificate(self):
        for name, what in (('x.ovf', 'descriptor'), ('x.mf', 'manifest'), ('./x.cert', 'certificate')):
            e = self._refused(ovf.FileReferenceError, _members(descriptor=_href(name)) + [('x.cert', b'')])
            self.assertEqual('The File "file1" has the ovf:href "%s", which names the %s: References may not hold the '
                             'descriptor, manifest or certificate' % (name, what), str(e))
        # Only the top-level ones are those: one in a subdirectory is an ordinary file.
        package = self._open(_members(descriptor=_href('sub/x.mf'), disks=[
            ('sub/x.mf', DISK1), ('disk2.vmdk', DISK2)]))
        self.assertEqual('sub/x.mf', package.uploads[0].member)

    def test_chunked_file(self):
        e = self._refused(ovf.ChunkedFileError, _members(descriptor=_file1(FILE1 + ' ovf:chunkSize="2"')))
        self.assertEqual('The File "file1" is split into chunks of 2 bytes (ovf:chunkSize), which the importer does '
                         'not join', str(e))

    def test_missing_member(self):
        e = self._refused(ovf.MissingMemberError, _members(disks=[('disk2.vmdk', DISK2)]))
        self.assertEqual(('disk1.vmdk',), e.members)

    def test_every_missing_member_in_references_order(self):
        # The archive's order is not References' order.
        descriptor = _add_file('ovf:href="tools.iso"')
        e = self._refused(ovf.MissingMemberError, _members(descriptor=descriptor, disks=[('disk2.vmdk', DISK2)]))
        self.assertEqual(('disk1.vmdk', 'tools.iso'), e.members)
        e = self._refused(ovf.MissingMemberError, _members(descriptor=descriptor, disks=[]))
        self.assertEqual(('disk1.vmdk', 'disk2.vmdk', 'tools.iso'), e.members)

    def test_member_that_is_not_a_regular_file(self):
        for kind, member in (('a symbolic link', synthetic.symlink('disk1.vmdk', 'disk2.vmdk')),
                             ('a hard link', synthetic.hardlink('disk1.vmdk', 'disk2.vmdk')),
                             ('a directory', synthetic.directory('disk1.vmdk')),
                             ('a FIFO', synthetic.fifo('disk1.vmdk')),
                             ('a device', synthetic.device('disk1.vmdk'))):
            e = self._refused(ovf.MemberTypeError, _members(descriptor=_file1('ovf:href="disk1.vmdk"'), disks=[
                ('disk2.vmdk', DISK2), member]))
            self.assertEqual('The File "file1" names the member "disk1.vmdk", which is %s, not a regular file' % kind,
                             str(e))

    def test_hard_link_to_a_file_is_still_refused(self):
        # Reading it would read its target, which holds the right bytes here.
        e = self._refused(ovf.MemberTypeError, _members(disks=[
            ('real.vmdk', DISK1), synthetic.hardlink('disk1.vmdk', 'real.vmdk'), ('disk2.vmdk', DISK2)]))
        self.assertIn('which is a hard link', str(e))

    def test_member_of_an_unknown_type(self):
        e = self._refused(ovf.MemberTypeError, _members(disks=[
            synthetic.Member(name='disk1.vmdk', type=b'V'), ('disk2.vmdk', DISK2)]))
        self.assertIn('which is a member of the tar type "V", not a regular file', str(e))

    def test_size_differs(self):
        e = self._refused(ovf.FileSizeError, _members(disks=[('disk1.vmdk', b'disk 1'), ('disk2.vmdk', DISK2)]))
        self.assertEqual('The File "file1" gives its ovf:size as 5 bytes, but its member "disk1.vmdk" holds 6 bytes',
                         str(e))

    def test_compressed_file(self):
        for compression in ('gzip', 'bzip2', 'Identity', ''):
            e = self._refused(ovf.CompressedFileError, _members(
                descriptor=_file1(FILE1 + ' ovf:compression="%s"' % compression)))
            self.assertEqual('The File "file1" has the ovf:compression "%s", and only uncompressed files are read'
                             % compression, str(e))

    def test_manifest_without_a_file(self):
        members = [('x.ovf', DESCRIPTOR), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)]
        e = self._refused(ovf.UnlistedFileError, members + [('x.mf', _manifest(members[:2]))])
        self.assertEqual('The manifest "x.mf" has no entry for "disk2.vmdk", the member of the File "file2"', str(e))

    def test_manifest_without_a_file_no_disk_uses(self):
        descriptor = _add_file('ovf:href="tools.iso"')
        members = [('x.ovf', descriptor), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)]
        e = self._refused(ovf.UnlistedFileError, members + [('tools.iso', b''), ('x.mf', _manifest(members))])
        self.assertIn('no entry for "tools.iso", the member of the File "file3"', str(e))

    def test_manifest_entry_names_the_member_less_its_dot_slash(self):
        members = [('x.ovf', DESCRIPTOR), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)]
        manifest = _manifest([('x.ovf', DESCRIPTOR), ('./disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)])
        e = self._refused(ovf.UnlistedFileError, members + [('x.mf', manifest)])
        self.assertIn('no entry for "disk1.vmdk"', str(e))

    def test_delta_disk(self):
        descriptor = _replace(DESCRIPTOR, '<Disk ovf:diskId="vmdisk2" ovf:fileRef="file2"',
                              '<Disk ovf:diskId="vmdisk2" ovf:fileRef="file2" ovf:parentRef="vmdisk1"')
        e = self._refused(ovf.DeltaDiskError, _members(descriptor=descriptor))
        self.assertEqual('The Disk "vmdisk2" is a delta disk of the Disk "vmdisk1" (ovf:parentRef): it holds only the '
                         'changes from its parent, and alone would not boot', str(e))

    def test_digest_of_a_disk_is_checked_on_request(self):
        # Opening checks only the descriptor's digest; the disks are read later.
        members = _members()
        package = self._open(members[:3] + [('disk2.vmdk', b'DISK2')])
        package.check_digest('disk1.vmdk', package.digests('disk1.vmdk', ['sha256']))
        e = self.assertRaises(ovf.DigestMismatchError, package.check_digest, 'disk2.vmdk',
                              package.digests('disk2.vmdk', ['sha256', 'sha512']))
        self.assertEqual('The SHA256 digest of "disk2.vmdk" is %s, but the manifest "x.mf" gives %s' % (
            _digest('sha256', b'DISK2'), _digest('sha256', DISK2)), str(e))

    def test_check_digest_needs_the_manifest_algorithm(self):
        package = self._open(_members())
        self.assertRaises(ValueError, package.check_digest, 'disk1.vmdk', package.digests('disk1.vmdk', ['sha512']))
        self.assertRaises(ValueError, package.check_digest, 'absent.vmdk', {'sha256': ''})


class OrderTestCase(PackageTestCase):
    """Each step of the reference checks runs over every File before the next starts."""

    def test_href_comes_before_the_member_of_an_earlier_file(self):
        descriptor = _replace(_href('absent.vmdk'), FILE2, 'ovf:href="http://example.com/disk2.vmdk"')
        self._refused(ovf.FileReferenceError, _members(descriptor=descriptor, disks=[]))

    def test_chunking_comes_before_the_member(self):
        self._refused(ovf.ChunkedFileError, _members(descriptor=_file1(FILE1 + ' ovf:chunkSize="2"'), disks=[
            ('disk2.vmdk', DISK2)]))
        descriptor = _replace(_href('absent.vmdk'), FILE2, FILE2 + ' ovf:chunkSize="2"')
        self._refused(ovf.ChunkedFileError, _members(descriptor=descriptor, disks=[]))

    def test_every_member_is_looked_for_before_any_type(self):
        e = self._refused(ovf.MissingMemberError, _members(descriptor=_file1('ovf:href="disk1.vmdk"'), disks=[
            synthetic.symlink('disk1.vmdk', 'elsewhere')]))
        self.assertEqual(('disk2.vmdk',), e.members)

    def test_type_comes_before_the_size_of_an_earlier_file(self):
        self._refused(ovf.MemberTypeError, _members(disks=[
            ('disk1.vmdk', b'wrong size'), synthetic.fifo('disk2.vmdk')]))

    def test_size_comes_before_the_compression_of_an_earlier_file(self):
        descriptor = _file1(FILE1 + ' ovf:compression="gzip"')
        self._refused(ovf.FileSizeError, _members(descriptor=descriptor, disks=[
            ('disk1.vmdk', DISK1), ('disk2.vmdk', b'wrong size')]))

    def test_member_comes_before_compression(self):
        # A descriptor-only copy of a compressed appliance, such as REMnux,
        # lacks its disk: the missing member is what is reported.
        e = self._refused(ovf.MissingMemberError, _members(descriptor=_file1(FILE1 + ' ovf:compression="gzip"'),
                                                           disks=[('disk2.vmdk', DISK2)]))
        self.assertEqual(('disk1.vmdk',), e.members)

    def test_compression_comes_before_the_manifest_entry_of_an_earlier_file(self):
        descriptor = _replace(DESCRIPTOR, FILE2, FILE2 + ' ovf:compression="gzip"')
        members = [('x.ovf', descriptor), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)]
        self._refused(ovf.CompressedFileError, members + [('x.mf', _manifest(members[:1] + members[2:]))])

    def test_manifest_entry_comes_before_a_delta_disk(self):
        descriptor = _replace(DESCRIPTOR, '<Disk ovf:diskId="vmdisk1" ovf:fileRef="file1"',
                              '<Disk ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:parentRef="vmdisk2"')
        members = [('x.ovf', descriptor), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)]
        self._refused(ovf.UnlistedFileError, members + [('x.mf', _manifest(members[:2]))])

    def test_descriptor_digest_comes_before_the_references(self):
        descriptor = _href('http://example.com/disk1.vmdk')
        manifest = _manifest([('x.ovf', DESCRIPTOR), ('disk1.vmdk', DISK1), ('disk2.vmdk', DISK2)])
        self._refused(ovf.DigestMismatchError, [('x.ovf', descriptor), ('x.mf', manifest), ('disk2.vmdk', DISK2)])


class HandwrittenFixtureTestCase(PackageTestCase):
    """The hand-written descriptors made for the archive checks, each wrapped in an OVA with a 1 MiB disk."""

    DISK = [('disk1.vmdk', b'0' * MIB)]

    def _wrapped(self, error, name, disks=DISK):
        return self._refused(error, [('x.ovf', _fixture(name))] + disks)

    def test_href_absolute_url(self):
        self._wrapped(ovf.FileReferenceError, 'href-absolute-url.ovf')

    def test_href_parent_dir(self):
        self._wrapped(ovf.FileReferenceError, 'href-parent-dir.ovf')

    def test_href_duplicate_member(self):
        e = self._wrapped(ovf.FileReferenceError, 'href-duplicate-member.ovf')
        self.assertIn('which the File "file1" names too', str(e))

    def test_href_missing_member(self):
        e = self._wrapped(ovf.MissingMemberError, 'href-missing-member.ovf')
        self.assertEqual(('missing-disk1.vmdk',), e.members)

    def test_gzip_reference(self):
        e = self._wrapped(ovf.CompressedFileError, 'gzip-reference.ovf')
        self.assertIn('"gzip"', str(e))

    def test_gzip_reference_without_its_member(self):
        e = self._wrapped(ovf.MissingMemberError, 'gzip-reference.ovf', disks=[])
        self.assertEqual(('disk1.vmdk',), e.members)

    def test_chunked_reference(self):
        self._wrapped(ovf.ChunkedFileError, 'chunked-reference.ovf')
        # A chunked file's href names no member, so its absence is not the error.
        self._wrapped(ovf.ChunkedFileError, 'chunked-reference.ovf', disks=[])


class GlanceTestCase(testtools.TestCase):
    """Glance's five test OVAs, used as they are."""

    def _refused(self, error, name):
        e = self.assertRaises(error, ovf.open_package, os.path.join(GLANCE, name))
        self.assertIs(error, type(e))
        return e

    def test_testserver(self):
        # Its ResourceAllocationSection is valid only in a VirtualSystemCollection.
        e = self._refused(ovf.UnparsedContentError, 'testserver.ova')
        self.assertIn('Envelope/VirtualSystem/ResourceAllocationSection', str(e))

    def test_bad_ovf(self):
        self._refused(ovf.MalformedDescriptorError, 'testserver-bad-ovf.ova')

    def test_no_disk(self):
        e = self._refused(ovf.MissingMemberError, 'testserver-no-disk.ova')
        self.assertEqual(('testserver-disk1.vmdk',), e.members)

    def test_no_ovf(self):
        e = self._refused(ovf.PackageLayoutError, 'testserver-no-ovf.ova')
        self.assertIn('holds no descriptor', str(e))

    def test_not_tar(self):
        e = self._refused(ovf.NotAnArchiveError, 'testserver-not-tar.ova')
        self.assertEqual('NotAnArchiveError(ReadError)', ovf.outcome_name(e))


class DigestsTestCase(PackageTestCase):
    def test_reads_in_pieces_and_reports_each(self):
        disk = bytes(range(256)) * (MIB * 5 // 2 // 256)
        package = self._open(_members(descriptor=_file1('ovf:href="disk1.vmdk"'), disks=[
            ('disk1.vmdk', disk), ('disk2.vmdk', DISK2)]))
        lengths = []
        digests = package.digests('disk1.vmdk', ['sha1', 'sha512'], lengths.append)
        self.assertEqual([MIB, MIB, MIB // 2], lengths)
        self.assertEqual({'sha1': _digest('sha1', disk), 'sha512': _digest('sha512', disk)}, digests)

    def test_empty_member(self):
        package = self._open(_members(descriptor=_file1('ovf:href="disk1.vmdk" ovf:size="0"'), disks=[
            ('disk1.vmdk', b''), ('disk2.vmdk', DISK2)]))
        lengths = []
        self.assertEqual({'sha256': _digest('sha256', b'')}, package.digests('disk1.vmdk', ['sha256'], lengths.append))
        self.assertEqual([], lengths)

    def test_no_algorithms(self):
        package = self._open(_members())
        self.assertEqual({}, package.digests('disk1.vmdk', []))

    def test_only_regular_members_are_read(self):
        members = _members()
        package = self._open(members + [synthetic.symlink('link', 'disk1.vmdk'), synthetic.directory('dir')])
        for name in ('link', 'dir'):
            self.assertRaises(ValueError, package.digests, name, ['sha256'])
            self.assertRaises(ValueError, package.open_member, name)
        self.assertRaises(KeyError, package.digests, 'absent.vmdk', ['sha256'])


class ClosingTestCase(PackageTestCase):
    def _recording(self):
        """A patch of tarfile.open that records each archive it opens in self.opened."""
        self.opened = []
        real_open = tarfile.open

        def recording(*args, **kwargs):
            archive = real_open(*args, **kwargs)
            self.opened.append(archive)
            return archive

        return mock.patch.object(tarfile, 'open', side_effect=recording)

    def test_with_block_closes_the_archive(self):
        self._build(_members())
        with self._recording():
            package = ovf.open_package(self.path)
        with package:
            self.assertEqual(1, len(self.opened))
            self.assertFalse(self.opened[0].closed)
            with package.open_member('disk1.vmdk') as f:
                self.assertEqual(DISK1, f.read())
        self.assertTrue(self.opened[0].closed)
        # Closing again does nothing.
        package.close()

    def test_close_closes_the_archive(self):
        self._build(_members())
        with self._recording():
            package = ovf.open_package(self.path)
        package.close()
        self.assertTrue(self.opened[0].closed)

    def test_refusal_closes_the_archive(self):
        for members in (_members() + [('y.ovf', b'')], _members(descriptor=_href('/disk1.vmdk'))):
            self._build(members)
            with self._recording():
                self.assertRaises(ovf.OVFError, ovf.open_package, self.path)
            self.assertEqual(1, len(self.opened))
            self.assertTrue(self.opened[0].closed)

    def test_plain_tar_only(self):
        self._build(_members())
        with self._recording() as opener:
            ovf.open_package(self.path).close()
        args, _ = opener.call_args
        self.assertEqual((self.path, 'r:'), args)
