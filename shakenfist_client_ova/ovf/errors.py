"""The OVF parser's errors.

The parser reports every failure by raising one of these. The command catches
OVFError, prints its message and exits; nothing in this package prints or exits.
"""


class OVFError(Exception):
    """The base class of every parser error. It is never raised itself."""


class ManifestError(OVFError):
    """A manifest does not parse, or cannot be read.

    That is a line that is not ALGORITHM(name)= digest, an algorithm other
    than SHA1, SHA256 or SHA512, a digest that is not hexadecimal of the
    algorithm's length, a second entry for one name, or a manifest that is
    not UTF-8.
    """


class UnknownAllocationUnitError(OVFError):
    """An allocation unit the parser cannot convert to bytes."""


class UnsupportedHardwareError(OVFError):
    """A hardware item of an unknown resource type, or a required "Other" item."""


class UnparsedContentError(OVFError):
    """Something in the descriptor is left after the parser has read what it understands."""


class MalformedDescriptorError(OVFError):
    """The descriptor is not well-formed XML."""


class EntityDeclarationError(OVFError):
    """The descriptor declares an entity, which no legitimate descriptor does."""


class UnsupportedEnvelopeError(OVFError):
    """The descriptor's root is not an Envelope in the OVF 1.x or 2.x namespace.

    That is an OVF 0.9 envelope, which the message names as such, a root in no
    namespace or an unknown one, or a root element that is not Envelope.
    """


class VirtualSystemCollectionError(OVFError):
    """The envelope holds a VirtualSystemCollection, several virtual machines rather than one.

    It is raised before any other check of the envelope's content.
    """


class UnsupportedProducerError(OVFError):
    """The descriptor is written in a producer's own dialect of OVF, which the parser does not read.

    An oVirt export, which declares the oVirt namespace, is refused with this.
    """


class MissingContentError(OVFError):
    """Something the descriptor must hold is absent, such as an envelope with no VirtualSystem."""


class InvalidValueError(OVFError):
    """A value does not parse as its type: a capacity that is not an integer, or a boolean neither true nor false.

    A capacity given as ${key} is one too when no ProductSection property has
    that key, or the property's value is not an integer. So is an id or key
    repeated where it must be unique, such as two Files with one ovf:id, and
    a value out of range, such as a Disk's ovf:populatedSize larger than its
    capacity or a Property's ovf:type that is not a property type.
    """


class BrokenReferenceError(OVFError):
    """A reference names something the descriptor does not hold.

    That is a drive whose HostResource names no Disk (ovf:/disk/<id>) or no
    File (ovf:/file/<id>), a drive whose Parent names no controller, a NIC
    whose Connection names no Network, a Disk whose ovf:fileRef names no File
    or whose ovf:parentRef names no Disk, or an ovf:configuration naming no
    Configuration in the DeploymentOptionSection.
    """


class NotAnArchiveError(OVFError):
    """The OVA cannot be read as an uncompressed tar archive.

    That is a file that is not a tar at all, a compressed tar, or an archive
    that ends early, including one that ends part way through a member being
    read. It is raised from the tarfile, EOFError or OSError exception that
    found the problem.
    """


class PackageLayoutError(OVFError):
    """The archive's members do not make an OVA package.

    The descriptor, manifest and certificate are the top-level members whose
    names end in .ovf, .mf and .cert. This is raised for two members with one
    name once a leading ./ is removed, for a package with no descriptor or
    more than one, more than one manifest or more than one certificate, for a
    certificate without a manifest, for a descriptor, manifest or certificate
    that is not a regular file, and for a descriptor or manifest larger than
    the parser will read.
    """


class FileReferenceError(OVFError):
    """A File's ovf:href cannot name a member of the archive.

    That is an href that is empty, has a URL scheme, starts with / or has a .
    or .. segment, two Files with one href, or an href naming the descriptor,
    manifest or certificate, none of which References may hold.
    """


class ChunkedFileError(OVFError):
    """A File is split into chunks, which the importer does not join.

    A File with ovf:chunkSize is refused before its member is looked for,
    because a chunked file's href names no member of its own.
    """


class MissingMemberError(OVFError):
    """Files in References name members the archive does not hold.

    Every File's member must exist, whether or not a Disk uses the File. All
    the missing members are reported in one error, in References order, and
    the members attribute holds their names as a tuple.
    """

    def __init__(self, members):
        self.members = tuple(members)
        if not self.members:
            raise ValueError('MissingMemberError needs at least one missing member')
        if len(self.members) == 1:
            what = 'a file'
        else:
            what = '%d files' % len(self.members)
        super().__init__('References names %s the archive does not hold: %s' % (
            what, ', '.join('"%s"' % member for member in self.members)))


class MemberTypeError(OVFError):
    """A File names a member that is not a regular file.

    The message says which kind it is: a symbolic link, a hard link, a
    directory, a device or a FIFO. Reading one would follow a link to another
    member, or read nothing.
    """


class FileSizeError(OVFError):
    """A File's ovf:size differs from the size of its member. The message gives both sizes."""


class CompressedFileError(OVFError):
    """A File's ovf:compression is neither absent nor identity, such as gzip, which the importer does not undo."""


class UnlistedFileError(OVFError):
    """The package has a manifest with no entry for the descriptor, or for a File's member."""


class DigestMismatchError(OVFError):
    """A member's digest differs from the one its manifest entry gives.

    The descriptor is checked before it is parsed, and every disk before any
    disk is uploaded. The message names the member and both digests.
    """


class DeltaDiskError(OVFError):
    """A Disk has an ovf:parentRef: it holds only the changes from its parent, and alone would not boot."""


def outcome_name(exc):
    """The name an outcome is recorded under in the expected files and the ledger.

    This is the exception's class name, followed by its cause's class name in
    brackets when it was raised from an exception that is not an OVFError, for
    example ManifestError(UnicodeDecodeError). The descriptor parser raises
    each of its errors itself, never from another exception, so its outcomes
    are bare class names.
    """
    name = type(exc).__name__
    cause = exc.__cause__
    if cause is not None and not isinstance(cause, OVFError):
        name = '%s(%s)' % (name, type(cause).__name__)
    return name
