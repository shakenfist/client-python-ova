"""The package reader: an OVA's archive, checked against its descriptor.

An OVA is a tar archive holding an OVF descriptor, at most one manifest and
certificate, and the files the descriptor's References name (DSP0243 clause
5). open_package() opens one, checks it, and returns a Package saying which
member is which and what the import should and should not read. Nothing here
prints, uploads or writes a file: the command reads the disks through the
Package's methods, and never through tarfile itself.

The archive must be an uncompressed tar, which DSP0243 5.3 says an OVA is. It
is checked in this order, and the first rule broken is the error raised:

1. The layout, before any member is read. Each member's name loses one
   leading ./, and no two members may then share a name. The top-level
   members, whose names have no /, that end in .ovf, .mf and .cert are the
   descriptor, the manifest and the certificate. There is exactly one
   descriptor, at most one manifest and at most one certificate, and a
   certificate needs a manifest, because it signs one. Each is a regular
   file, the descriptor at most MAX_DESCRIPTOR_SIZE bytes and the manifest at
   most MAX_MANIFEST_SIZE, so that an untrusted member cannot exhaust memory
   before it is parsed. Member order is not checked.
2. The descriptor's digest. With a manifest, the manifest is read and parsed
   first, wherever it sits, and must give the descriptor a digest that the
   descriptor's bytes match.
3. The descriptor, through parse_descriptor().
4. The References. Each step runs over every File before the next starts,
   so a refusal reports the first rule broken:
   1. The href names a member: it is not empty, has no URL scheme, does not
      start with /, and has no . or .. segment once one leading ./ is
      removed. No two Files name one member, and none names the descriptor,
      manifest or certificate. An href is compared with member names as
      text, never percent-decoded.
   2. No File is chunked (ovf:chunkSize). A chunked file's href names no
      member of its own, so this comes before the member is looked for.
   3. Every File's member exists, whether or not a Disk uses the File, and
      every missing one is reported together. Then each is a regular file.
   4. A File's ovf:size, where it is given, is its member's size.
   5. No File is compressed: ovf:compression is absent or identity.
   6. With a manifest, every File's member has an entry. Entries naming
      neither the descriptor nor a File's member are returned, not refused.
   7. No Disk is a delta disk (ovf:parentRef).

A manifest entry names a member as it is named once a leading ./ is removed.
Every digest is compared without regard to case. The manifest detects
corruption and accidental mismatch, not tampering: anyone who can change the
descriptor can rewrite the manifest, and the certificate is not checked.
"""

from dataclasses import dataclass, field
import hashlib
import io
import posixpath
import re
import tarfile
from typing import Dict, List, Optional

from .descriptor import parse_descriptor
from .errors import (
    ChunkedFileError, CompressedFileError, DeltaDiskError, DigestMismatchError, FileReferenceError, FileSizeError,
    MemberTypeError, MissingMemberError, NotAnArchiveError, PackageLayoutError, UnlistedFileError)
from .manifest import parse_manifest
from .model import Disk, Envelope, File, Manifest, ManifestEntry


# The largest descriptor and manifest read into memory. The largest descriptor
# in the upstream corpus is 6.3 MB, and a manifest has a line per file.
MAX_DESCRIPTOR_SIZE = 16 * 1024 * 1024
MAX_MANIFEST_SIZE = 1024 * 1024

# Members are hashed in reads of this size.
READ_SIZE = 1024 * 1024

# What tarfile raises for an archive it cannot read: its own errors, and those
# of the file underneath. Only tarfile's calls are wrapped, never the parser's.
TAR_ERRORS = (tarfile.TarError, EOFError, OSError)

# The suffixes of the descriptor, the manifest and the certificate.
DESCRIPTOR_SUFFIX = '.ovf'
MANIFEST_SUFFIX = '.mf'
CERTIFICATE_SUFFIX = '.cert'

# An href that starts with a URL scheme, as RFC 3986 spells one.
_SCHEME_RE = re.compile(r'^[A-Za-z][A-Za-z0-9+.-]*:')

# The ovf:compression values of an uncompressed file: none, or identity, which
# DSP0243 7.1 defines as the same.
UNCOMPRESSED = (None, 'identity')


@dataclass
class Upload:
    """A disk to upload: a Disk with an ovf:fileRef, the File it names, and the member holding that File."""
    disk: Disk
    file: File
    member: str


@dataclass
class Package:
    """An open OVA, checked against its descriptor.

    Member names are as the archive gives them once a leading ./ is removed.
    open_package() returns one holding the archive open, and closes it when a
    with block around it ends, or when close() is called. The methods read
    the archive, so they work only while it is open.
    """
    descriptor_member: str
    envelope: Envelope
    manifest_member: Optional[str] = None
    certificate_member: Optional[str] = None
    manifest: Optional[Manifest] = None
    file_members: Dict[str, str] = field(default_factory=dict)  # each File's id, and the member holding it
    uploads: List[Upload] = field(default_factory=list)  # one per Disk with an ovf:fileRef, in DiskSection order
    blank_disks: List[Disk] = field(default_factory=list)  # the Disks with no file, created empty at deployment
    unused_files: List[File] = field(default_factory=list)  # the Files no Disk names, such as an ISO
    # The members nothing references, in archive order: neither the descriptor,
    # the manifest, the certificate nor a File's member. Directories are left out.
    unreferenced_members: List[str] = field(default_factory=list)
    # The manifest's entries naming neither the descriptor nor a File's member.
    unreferenced_entries: List[ManifestEntry] = field(default_factory=list)
    _archive: Optional[tarfile.TarFile] = field(default=None, init=False, repr=False, compare=False)
    _members: Dict[str, tarfile.TarInfo] = field(default_factory=dict, init=False, repr=False, compare=False)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()

    def close(self):
        if self._archive is not None:
            self._archive.close()

    @property
    def manifest_name_differs(self):
        """Whether there is a manifest whose base name is not the descriptor's, which DSP0243 5.1 says it is."""
        if self.manifest_member is None:
            return False
        return posixpath.splitext(self.manifest_member)[0] != posixpath.splitext(self.descriptor_member)[0]

    def manifest_entry(self, member):
        """The manifest's entry for a member, or None when there is no manifest or it has no entry for the member."""
        if self.manifest is None:
            return None
        return _entry(self.manifest, member)

    def _regular(self, member):
        info = self._members[member]
        if not info.isfile():
            raise ValueError('"%s" is %s, not a regular file, and is never read' % (member, _kind(info)))
        return info

    def member_size(self, member):
        """A regular member's size in bytes, as its tar header gives it."""
        return self._regular(member).size

    def digests(self, member, algorithms, progress=None):
        """Read a regular member once, returning its digest in each of algorithms, as a dict of hexdigests.

        algorithms are hashlib names, as a ManifestEntry gives them, such as
        'sha256'. The member is read in READ_SIZE pieces, and progress, if it
        is given, is called with each piece's length. An archive that cannot
        be read, or that ends before the member does, is a NotAnArchiveError.
        """
        info = self._regular(member)
        hashes = {algorithm: hashlib.new(algorithm) for algorithm in algorithms}
        length = 0
        with _extract(self._archive, info, member) as f:
            while True:
                data = _read(f, READ_SIZE, member)
                if not data:
                    break
                length += len(data)
                for h in hashes.values():
                    h.update(data)
                if progress is not None:
                    progress(len(data))
        _check_length(member, info, length)
        return {algorithm: h.hexdigest() for algorithm, h in hashes.items()}

    def check_digest(self, member, digests):
        """Check a member's digests, as digests() returns them, against the member's manifest entry.

        Raises DigestMismatchError, naming the member and both digests, when
        the entry's algorithm gives a different digest. Raises ValueError when
        the member has no manifest entry, or digests lacks its algorithm.
        """
        entry = self.manifest_entry(member)
        if entry is None:
            raise ValueError('"%s" has no manifest entry to check its digest against' % member)
        if entry.algorithm not in digests:
            raise ValueError('"%s" needs its %s digest checked, which was not computed'
                             % (member, entry.algorithm.upper()))
        _check_digest(self.manifest_member, entry, digests[entry.algorithm])

    def open_member(self, member):
        """A seekable, binary file object reading a regular member, for an upload. Close it after use.

        It is a MemberFile: it has read(), seek(), tell(), close() and closed,
        and is a context manager. An archive that cannot be read, or that ends
        before the member does, is a NotAnArchiveError from whichever of these
        finds it, however far into the member the reader is.
        """
        info = self._regular(member)
        return MemberFile(_extract(self._archive, info, member), member, info.size)


class MemberFile:
    """A member opened for reading, which raises NotAnArchiveError where tarfile would raise its own errors.

    A read that finds the end of the member before its size, as its tar
    header gives it, is a NotAnArchiveError too, rather than the end of a
    shorter file.
    """

    def __init__(self, f, member, size):
        self._file = f
        self._member = member
        self._size = size

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()

    def read(self, size=-1):
        """Up to size bytes, or the rest of the member when size is negative or None."""
        data = _read(self._file, size, self._member)
        if not data and size != 0:
            length = self.tell()
            if length < self._size:
                raise _ends_early(self._member, length, self._size)
        return data

    def seek(self, offset, whence=io.SEEK_SET):
        try:
            return self._file.seek(offset, whence)
        except TAR_ERRORS as e:
            raise _cannot_read_member(self._member, e) from e

    def tell(self):
        try:
            return self._file.tell()
        except TAR_ERRORS as e:
            raise _cannot_read_member(self._member, e) from e

    def readable(self):
        return True

    def seekable(self):
        return True

    @property
    def closed(self):
        return self._file.closed

    def close(self):
        self._file.close()


def _cannot_read(e):
    return NotAnArchiveError('The OVA cannot be read as an uncompressed tar archive, which an OVA must be: %s: %s'
                             % (type(e).__name__, e))


def _cannot_read_member(member, e):
    return NotAnArchiveError('Could not read "%s" from the OVA: %s: %s' % (member, type(e).__name__, e))


def _extract(archive, info, member):
    try:
        return archive.extractfile(info)
    except TAR_ERRORS as e:
        raise _cannot_read_member(member, e) from e


def _read(f, size, member):
    try:
        return f.read(size)
    except TAR_ERRORS as e:
        raise _cannot_read_member(member, e) from e


def _check_length(member, info, length):
    if length != info.size:
        raise _ends_early(member, length, info.size)


def _ends_early(member, length, size):
    return NotAnArchiveError('The OVA ends part way through "%s": %d of its %d bytes could be read'
                             % (member, length, size))


def _read_whole(archive, member, info):
    """A regular member's bytes. Its size was checked against a limit before this is called."""
    with _extract(archive, info, member) as f:
        data = _read(f, None, member)
    _check_length(member, info, len(data))
    return data


def _kind(info):
    """What a member that is not a regular file is, for a message."""
    if info.issym():
        return 'a symbolic link'
    if info.islnk():
        return 'a hard link'
    if info.isdir():
        return 'a directory'
    # TarInfo.isdev() is true of a FIFO as well as a device.
    if info.isfifo():
        return 'a FIFO'
    if info.isdev():
        return 'a device'
    return 'a member of the tar type "%s"' % info.type.decode('ascii', 'backslashreplace')


def _strip(name):
    """A name less one leading ./, as members and hrefs are compared."""
    return name[2:] if name.startswith('./') else name


def _list(archive):
    """Every member, in archive order, as (name, TarInfo), its name less one leading ./, refusing a repeated name."""
    try:
        infos = archive.getmembers()
    except TAR_ERRORS as e:
        raise _cannot_read(e) from e

    members = []
    seen = {}
    for info in infos:
        name = _strip(info.name)
        first = seen.get(name)
        if first is not None:
            written = '' if first.name == info.name else ' (written "%s" and "%s")' % (first.name, info.name)
            raise PackageLayoutError(
                'The archive holds two members named "%s"%s, and DSP0243 allows each member only once'
                % (name, written))
        seen[name] = info
        members.append((name, info))
    return members


def _package_member(members, suffix, what):
    """The one top-level member whose name ends in suffix, or None, refusing more than one."""
    found = [name for name, _ in members if '/' not in name and name.endswith(suffix)]
    if len(found) > 1:
        raise PackageLayoutError('The archive holds more than one %s: %s' % (
            what, ', '.join('"%s"' % name for name in found)))
    return found[0] if found else None


def _check_package_member(infos, member, what, limit=None):
    info = infos[member]
    if not info.isfile():
        raise PackageLayoutError('The %s "%s" is %s, not a regular file' % (what, member, _kind(info)))
    if limit is not None and info.size > limit:
        raise PackageLayoutError('The %s "%s" is %d bytes, more than the %d bytes the parser reads'
                                 % (what, member, info.size, limit))


def _entry(manifest, name):
    for entry in manifest.entries:
        if entry.name == name:
            return entry
    return None


def _check_digest(manifest_member, entry, computed):
    if computed.lower() != entry.digest.lower():
        raise DigestMismatchError('The %s digest of "%s" is %s, but the manifest "%s" gives %s' % (
            entry.algorithm.upper(), entry.name, computed, manifest_member, entry.digest))


def _check_hrefs(files, package_members):
    """Each File's member name, by File id, refusing an href that cannot name a member of the archive."""
    members = {}
    named_by = {}
    for file in files:
        name = _strip(file.href)
        where = 'The File "%s" has the ovf:href "%s"' % (file.id, file.href)
        if not name:
            raise FileReferenceError('%s, which names no member' % where)
        if _SCHEME_RE.match(file.href):
            raise FileReferenceError('%s, which has a URL scheme: an href names a member of the archive' % where)
        if file.href.startswith('/'):
            raise FileReferenceError('%s, which starts with /: an href names a member of the archive' % where)
        segments = name.split('/')
        if '.' in segments or '..' in segments:
            raise FileReferenceError('%s, which has a . or .. segment, so names no member of the archive' % where)
        if name in package_members:
            raise FileReferenceError('%s, which names the %s: References may not hold the descriptor, manifest or '
                                     'certificate' % (where, package_members[name]))
        if name in named_by:
            raise FileReferenceError('%s, naming the member "%s", which the File "%s" names too' % (
                where, name, named_by[name]))
        named_by[name] = file.id
        members[file.id] = name
    return members


def _check_references(envelope, manifest, manifest_member, infos, file_members):
    """Check the Files' members and the Disks, each step over every File or Disk before the next."""
    files = envelope.files

    for file in files:
        if file.chunk_size is not None:
            raise ChunkedFileError('The File "%s" is split into chunks of %d bytes (ovf:chunkSize), which the '
                                   'importer does not join' % (file.id, file.chunk_size))

    missing = [file_members[file.id] for file in files if file_members[file.id] not in infos]
    if missing:
        raise MissingMemberError(missing)
    for file in files:
        info = infos[file_members[file.id]]
        if not info.isfile():
            raise MemberTypeError('The File "%s" names the member "%s", which is %s, not a regular file' % (
                file.id, file_members[file.id], _kind(info)))

    for file in files:
        size = infos[file_members[file.id]].size
        if file.size is not None and file.size != size:
            raise FileSizeError('The File "%s" gives its ovf:size as %d bytes, but its member "%s" holds %d bytes'
                                % (file.id, file.size, file_members[file.id], size))

    for file in files:
        if file.compression not in UNCOMPRESSED:
            raise CompressedFileError('The File "%s" has the ovf:compression "%s", and only uncompressed files are '
                                      'read' % (file.id, file.compression))

    if manifest is not None:
        for file in files:
            if _entry(manifest, file_members[file.id]) is None:
                raise UnlistedFileError('The manifest "%s" has no entry for "%s", the member of the File "%s"' % (
                    manifest_member, file_members[file.id], file.id))

    for disk in envelope.disks:
        if disk.parent_ref is not None:
            raise DeltaDiskError('The Disk "%s" is a delta disk of the Disk "%s" (ovf:parentRef): it holds only the '
                                 'changes from its parent, and alone would not boot' % (disk.disk_id, disk.parent_ref))


def _check_layout(members, infos):
    """The descriptor's, manifest's and certificate's names, the last two None if absent, refusing a bad layout."""
    descriptor = _package_member(members, DESCRIPTOR_SUFFIX, 'descriptor')
    if descriptor is None:
        raise PackageLayoutError('The archive holds no descriptor: no top-level member\'s name ends in .ovf')
    manifest = _package_member(members, MANIFEST_SUFFIX, 'manifest')
    certificate = _package_member(members, CERTIFICATE_SUFFIX, 'certificate')
    if certificate is not None and manifest is None:
        raise PackageLayoutError('The archive holds the certificate "%s" but no manifest, and a certificate signs '
                                 'the manifest' % certificate)

    _check_package_member(infos, descriptor, 'descriptor', MAX_DESCRIPTOR_SIZE)
    if manifest is not None:
        _check_package_member(infos, manifest, 'manifest', MAX_MANIFEST_SIZE)
    if certificate is not None:
        _check_package_member(infos, certificate, 'certificate')
    return descriptor, manifest, certificate


def _read_descriptor(archive, infos, descriptor, manifest_member):
    """The manifest, or None, and the descriptor's Envelope, its bytes checked against the manifest before parsing."""
    if manifest_member is None:
        return None, parse_descriptor(_read_whole(archive, descriptor, infos[descriptor]))

    manifest = parse_manifest(_read_whole(archive, manifest_member, infos[manifest_member]))
    entry = _entry(manifest, descriptor)
    if entry is None:
        raise UnlistedFileError('The manifest "%s" has no entry for the descriptor "%s"' % (
            manifest_member, descriptor))
    data = _read_whole(archive, descriptor, infos[descriptor])
    _check_digest(manifest_member, entry, hashlib.new(entry.algorithm, data).hexdigest())
    return manifest, parse_descriptor(data)


def _read_package(archive):
    members = _list(archive)
    infos = dict(members)
    descriptor, manifest_member, certificate = _check_layout(members, infos)
    manifest, envelope = _read_descriptor(archive, infos, descriptor, manifest_member)

    package_members = {descriptor: 'descriptor'}
    if manifest_member is not None:
        package_members[manifest_member] = 'manifest'
    if certificate is not None:
        package_members[certificate] = 'certificate'
    file_members = _check_hrefs(envelope.files, package_members)
    _check_references(envelope, manifest, manifest_member, infos, file_members)

    files = {file.id: file for file in envelope.files}
    used = set(disk.file_ref for disk in envelope.disks if disk.file_ref is not None)
    referenced = set(package_members) | set(file_members.values())
    covered = set([descriptor]) | set(file_members.values())
    package = Package(
        descriptor_member=descriptor,
        envelope=envelope,
        manifest_member=manifest_member,
        certificate_member=certificate,
        manifest=manifest,
        file_members=file_members,
        uploads=[Upload(disk=disk, file=files[disk.file_ref], member=file_members[disk.file_ref])
                 for disk in envelope.disks if disk.file_ref is not None],
        blank_disks=[disk for disk in envelope.disks if disk.file_ref is None],
        unused_files=[file for file in envelope.files if file.id not in used],
        unreferenced_members=[name for name, info in members if name not in referenced and not info.isdir()],
        unreferenced_entries=[entry for entry in (manifest.entries if manifest else []) if entry.name not in covered])
    package._archive = archive
    package._members = infos
    return package


def open_package(path):
    """Open the OVA at path and check it against its descriptor, returning a Package.

    The Package holds the archive open: use it as a context manager, which
    closes the archive as the with block ends, or call its close(). Raises an
    OVFError subclass for every refusal, closing the archive first.
    """
    try:
        archive = tarfile.open(path, 'r:', encoding='utf-8')
    except TAR_ERRORS as e:
        raise _cannot_read(e) from e
    try:
        return _read_package(archive)
    except BaseException:
        archive.close()
        raise
