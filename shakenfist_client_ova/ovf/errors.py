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


class UnsupportedDescriptorError(OVFError):
    """Any other failure inside the descriptor parser, raised from the original exception.

    It exists only until the parser names each of these failures itself, when
    this class goes (see docs/plans/PLAN-ovf-parser.md).
    """


def outcome_name(exc):
    """The name an outcome is recorded under in the expected files and the ledger.

    This is the exception's class name, followed by its cause's class name in
    brackets when it was raised from an exception that is not an OVFError, for
    example UnsupportedDescriptorError(KeyError).
    """
    name = type(exc).__name__
    cause = exc.__cause__
    if cause is not None and not isinstance(cause, OVFError):
        name = '%s(%s)' % (name, type(cause).__name__)
    return name
