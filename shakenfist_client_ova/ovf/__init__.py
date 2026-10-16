"""An OVF descriptor and manifest parser.

This subpackage is built to be spun out. It imports only the standard library
and defusedxml (and, until phase 3 of docs/plans/PLAN-ovf-parser.md, xmltodict
and dpath). It never imports click or shakenfist_client, never prints and
never exits: it raises OVFError subclasses and returns the dataclasses in
model.py. tests/test_ovf_boundary.py enforces this.
"""

from .errors import (
    EntityDeclarationError, MalformedDescriptorError, ManifestError, OVFError, outcome_name,
    UnknownAllocationUnitError, UnparsedContentError, UnsupportedDescriptorError, UnsupportedHardwareError)
from .model import (
    Controller, DeploymentOption, Disk, DiskDrive, Envelope, Eula, File, Manifest, ManifestEntry, Network, Nic,
    OperatingSystem, Product, Property, to_json, VirtualHardware, VirtualSystem)
from .descriptor import parse_descriptor
from .manifest import parse_manifest


__all__ = [
    # errors.py
    'EntityDeclarationError', 'MalformedDescriptorError', 'ManifestError', 'OVFError', 'outcome_name',
    'UnknownAllocationUnitError', 'UnparsedContentError', 'UnsupportedDescriptorError', 'UnsupportedHardwareError',
    # model.py
    'Controller', 'DeploymentOption', 'Disk', 'DiskDrive', 'Envelope', 'Eula', 'File', 'Manifest', 'ManifestEntry',
    'Network', 'Nic', 'OperatingSystem', 'Product', 'Property', 'to_json', 'VirtualHardware', 'VirtualSystem',
    # descriptor.py and manifest.py
    'parse_descriptor', 'parse_manifest',
]
