"""An OVF descriptor and manifest parser.

This subpackage is built to be spun out. It imports only the standard library
and defusedxml (and, until the parser moves to ElementTree, xmltodict and
dpath; see docs/plans/PLAN-ovf-parser.md). It never imports click or shakenfist_client, never prints and
never exits: it raises OVFError subclasses and returns the dataclasses in
model.py. tests/test_ovf_boundary.py enforces this.
"""

from .errors import (
    BrokenReferenceError, EntityDeclarationError, InvalidValueError, MalformedDescriptorError, ManifestError,
    MissingContentError, OVFError, outcome_name, UnknownAllocationUnitError, UnparsedContentError,
    UnsupportedDescriptorError, UnsupportedEnvelopeError, UnsupportedHardwareError, UnsupportedProducerError,
    VirtualSystemCollectionError)
from .model import (
    Controller, DeploymentOption, Disk, DiskDrive, Envelope, Eula, File, Manifest, ManifestEntry, Network, Nic,
    OperatingSystem, Product, Property, to_json, VirtualHardware, VirtualSystem)
from .descriptor import parse_descriptor
from .manifest import parse_manifest


__all__ = [
    # errors.py
    'BrokenReferenceError', 'EntityDeclarationError', 'InvalidValueError', 'MalformedDescriptorError',
    'ManifestError', 'MissingContentError', 'OVFError', 'outcome_name', 'UnknownAllocationUnitError',
    'UnparsedContentError', 'UnsupportedDescriptorError', 'UnsupportedEnvelopeError', 'UnsupportedHardwareError',
    'UnsupportedProducerError', 'VirtualSystemCollectionError',
    # model.py
    'Controller', 'DeploymentOption', 'Disk', 'DiskDrive', 'Envelope', 'Eula', 'File', 'Manifest', 'ManifestEntry',
    'Network', 'Nic', 'OperatingSystem', 'Product', 'Property', 'to_json', 'VirtualHardware', 'VirtualSystem',
    # descriptor.py and manifest.py
    'parse_descriptor', 'parse_manifest',
]
