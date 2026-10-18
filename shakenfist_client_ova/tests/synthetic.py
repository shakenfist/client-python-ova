"""Build synthetic OVAs for the tests.

Real appliances are tidy: every member is a regular file with a plain name.
The archive checks also have to be tested against what no surveyed producer
writes, such as ./ prefixed names, two members with one name, links,
directories and compressed or truncated archives, so the tests build those
here rather than committing binaries.

build() writes a USTAR tar, the format an OVA uses, from a list of members.
Each member is one of:

* (name, data), a regular file holding the bytes data;
* regular(name, data), the same;
* symlink(name, target) and hardlink(name, target), links to target, which
  need not be a member;
* directory(name);
* fifo(name) and device(name), a FIFO and a character device.

Names are written exactly as given, so a ./ prefix is kept, and members are
written in the order given, so two may share a name. Every member has the
same owner, mode and time, so one list always builds the same bytes. The
archive is written to a path the caller chooses, normally in a temporary
directory the test owns:

    with tempfile.TemporaryDirectory() as tmpdir:
        path = synthetic.build(os.path.join(tmpdir, 'x.ova'), [
            ('x.ovf', descriptor),
            ('x.mf', manifest),
            synthetic.symlink('disk1.vmdk', 'elsewhere.vmdk'),
        ])
"""

from dataclasses import dataclass
import gzip
import hashlib
import io
import os
import tarfile


@dataclass
class Member:
    name: str
    type: bytes                     # a tarfile type, such as tarfile.REGTYPE
    data: bytes = b''               # a regular file's content
    target: str = ''                # a link's target


def regular(name, data):
    """A regular file holding data, which is bytes."""
    return Member(name=name, type=tarfile.REGTYPE, data=data)


def symlink(name, target):
    """A symbolic link to target."""
    return Member(name=name, type=tarfile.SYMTYPE, target=target)


def hardlink(name, target):
    """A hard link to target, which reading the member follows when target is in the archive."""
    return Member(name=name, type=tarfile.LNKTYPE, target=target)


def directory(name):
    """A directory. tarfile writes its name with a trailing / and reads it back without one."""
    return Member(name=name, type=tarfile.DIRTYPE)


def fifo(name):
    """A FIFO."""
    return Member(name=name, type=tarfile.FIFOTYPE)


def device(name):
    """A character device."""
    return Member(name=name, type=tarfile.CHRTYPE)


MODES = {
    tarfile.DIRTYPE: 0o755,
    tarfile.SYMTYPE: 0o777,
}


def _member(member):
    if isinstance(member, Member):
        return member
    name, data = member
    return regular(name, data)


def _tar(members):
    """The bytes of a USTAR tar of members, and the offset where its last member's data starts."""
    buffer = io.BytesIO()
    last_data = None
    with tarfile.open(fileobj=buffer, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for member in members:
            info = tarfile.TarInfo(member.name)
            info.type = member.type
            info.mode = MODES.get(member.type, 0o644)
            info.mtime = 0
            info.linkname = member.target
            info.size = len(member.data)
            # A USTAR header is one block, with the member's data straight after it.
            last_data = archive.offset + tarfile.BLOCKSIZE
            archive.addfile(info, io.BytesIO(member.data) if member.type == tarfile.REGTYPE else None)
    return buffer.getvalue(), last_data


def build(path, members, compressed=False, truncated=False):
    """Write an OVA of members, in order, to path, and return path.

    members is a list of Members, or of (name, data) pairs for regular files.
    With compressed, the tar is gzip compressed, which no OVA should be. With
    truncated, the archive stops half way through its last member's data,
    with no end-of-archive blocks after it, as a download cut short would; the
    last member must then be a regular file of at least two bytes. tarfile
    still reads every header, but raises its ReadError for a read of the last
    member, and for listing the archive once it steps past that member, as
    getmembers() and getnames() do. A member that USTAR cannot hold, such as
    a name longer than it allows, raises tarfile's ValueError.
    """
    members = [_member(member) for member in members]
    data, last_data = _tar(members)
    if truncated:
        if not members or members[-1].type != tarfile.REGTYPE or len(members[-1].data) < 2:
            raise ValueError('a truncated archive needs a last member that is a regular file of two bytes or more')
        data = data[:last_data + len(members[-1].data) // 2]

    with open(path, 'wb') as f:
        if compressed:
            with gzip.GzipFile(filename='', mode='wb', fileobj=f, mtime=0) as compressor:
                compressor.write(data)
        else:
            f.write(data)
    return path


def replace(data, old, new):
    """Bytes with every occurrence of the text old replaced by new, which must occur."""
    text = data.decode()
    assert old in text, old
    return text.replace(old, new).encode()


def digest(algorithm, data):
    """The hexadecimal digest of data in the algorithm, which is named in any case."""
    return hashlib.new(algorithm.lower(), data).hexdigest()


def manifest(members, algorithm='SHA256'):
    """A manifest giving each member its digest in the algorithm, which is written as given.

    members are (name, data) pairs or Members, whose data is empty unless they
    are regular files.
    """
    pairs = [(member.name, member.data) if isinstance(member, Member) else member for member in members]
    return ''.join('%s(%s)= %s\n' % (algorithm, name, digest(algorithm, data)) for name, data in pairs).encode()


# The hand-written two-controllers descriptor with its files' ovf:size cut to five bytes, so that its disks are
# small and can differ from each other, and the disks and File attributes that go with it.
HANDWRITTEN = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures', 'ovf', 'handwritten')
with open(os.path.join(HANDWRITTEN, 'two-controllers.ovf'), 'rb') as _f:
    TWO_CONTROLLERS = _f.read()
SMALL_TWO_CONTROLLERS = replace(TWO_CONTROLLERS, 'ovf:size="1048576"', 'ovf:size="5"')
DISK1 = b'disk1'
DISK2 = b'disk2'
FILE1 = 'ovf:href="disk1.vmdk" ovf:size="5"'
