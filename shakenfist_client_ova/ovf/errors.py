"""The OVF parser's errors.

The parser reports every failure by raising one of these. The command catches
OVFError, prints its message and exits; nothing in this package prints or exits.
"""


class OVFError(Exception):
    """The base class of every parser error. It is never raised itself."""


class ManifestError(OVFError):
    """A manifest does not parse: a line that is malformed, or a manifest that cannot be read."""


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
    that key, or the property's value is not an integer.
    """


class BrokenReferenceError(OVFError):
    """A reference names something the descriptor does not hold.

    That is a drive whose HostResource names no Disk (ovf:/disk/<id>) or no
    File (ovf:/file/<id>), a drive whose Parent names no controller, a Disk
    whose ovf:fileRef names no File, or an ovf:configuration naming no
    Configuration in the DeploymentOptionSection.
    """


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
