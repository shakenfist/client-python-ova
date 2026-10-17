"""An OVF descriptor and manifest parser, and a reader of the OVA around them.

This subpackage is built to be spun out. It imports only the standard library
and defusedxml. It never imports click or shakenfist_client, never prints and
never exits: it raises OVFError subclasses and returns the dataclasses in
model.py, or from open_package() a Package, in package.py, which also reads
the archive's members. tests/test_ovf_boundary.py enforces this.
"""

from .errors import (
    BrokenReferenceError, ChunkedFileError, CompressedFileError, DeltaDiskError, DigestMismatchError,
    EntityDeclarationError, FileReferenceError, FileSizeError, InvalidValueError, MalformedDescriptorError,
    ManifestError, MemberTypeError, MissingContentError, MissingMemberError, NotAnArchiveError, OVFError,
    outcome_name, PackageLayoutError, UnknownAllocationUnitError, UnlistedFileError, UnparsedContentError,
    UnsupportedEnvelopeError, UnsupportedHardwareError, UnsupportedProducerError, VirtualSystemCollectionError)
from .model import (
    Controller, DeploymentOption, Disk, DiskDrive, Envelope, Eula, File, Manifest, ManifestEntry, Network, Nic,
    OperatingSystem, Product, Property, to_json, VirtualHardware, VirtualSystem)
from .descriptor import parse_descriptor
from .manifest import parse_manifest
from .package import open_package, Package, Upload


__all__ = [
    # errors.py
    'BrokenReferenceError', 'ChunkedFileError', 'CompressedFileError', 'DeltaDiskError', 'DigestMismatchError',
    'EntityDeclarationError', 'FileReferenceError', 'FileSizeError', 'InvalidValueError', 'MalformedDescriptorError',
    'ManifestError', 'MemberTypeError', 'MissingContentError', 'MissingMemberError', 'NotAnArchiveError',
    'OVFError', 'outcome_name', 'PackageLayoutError', 'UnknownAllocationUnitError', 'UnlistedFileError',
    'UnparsedContentError', 'UnsupportedEnvelopeError', 'UnsupportedHardwareError', 'UnsupportedProducerError',
    'VirtualSystemCollectionError',
    # model.py
    'Controller', 'DeploymentOption', 'Disk', 'DiskDrive', 'Envelope', 'Eula', 'File', 'Manifest', 'ManifestEntry',
    'Network', 'Nic', 'OperatingSystem', 'Product', 'Property', 'to_json', 'VirtualHardware', 'VirtualSystem',
    # descriptor.py and manifest.py
    'parse_descriptor', 'parse_manifest',
    # package.py
    'open_package', 'Package', 'Upload',
]
