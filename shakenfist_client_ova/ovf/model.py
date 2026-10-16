"""What the OVF parser returns: plain dataclasses, and their one serialisation.

Lists keep document order. Sizes are integers in bytes; any conversion to MiB
or GiB is the command's. Fields commented "not read yet" exist so that the
serialised shape is final; the parser does not fill them yet, and they hold
None or an empty list. See docs/plans/PLAN-ovf-parser.md. Each class lists its
required fields first, because a dataclass refuses a field without a default
after one with a default; to_json sorts keys, so the order never reaches an
expected file.

While the parser still walks xmltodict's output, a field typed str may hold
None when the walk did not refuse that value's absence. Once the parser moves
to ElementTree, a missing required value is refused instead.
"""

import dataclasses
from dataclasses import dataclass, field
import json
from typing import List, Optional


@dataclass
class File:                                     # References/File
    id: str
    href: str
    size: Optional[int] = None                  # not read yet; will be checked against the archive member
    compression: Optional[str] = None           # not read yet; a gzip reference will be refused
    chunk_size: Optional[int] = None            # not read yet; a chunked reference will be refused


@dataclass
class Disk:                                     # DiskSection/Disk
    disk_id: str
    capacity_bytes: int                         # ovf:capacity x its allocation units
    file_ref: Optional[str] = None
    format: Optional[str] = None
    populated_size: Optional[int] = None        # not read yet
    interface: Optional[str] = None             # not read yet: ovf:disk-interface, the disk bus (oVirt writes it)


@dataclass
class Network:                                  # NetworkSection/Network
    name: str
    description: Optional[str] = None


@dataclass
class Controller:                               # ResourceType 5, 6, and 20 with subtype AHCI
    instance_id: str
    bus: str                                    # 'ide', 'scsi' or 'sata'


@dataclass
class DiskDrive:                                # ResourceType 17
    parent: str                                 # the controller's instance_id
    address_on_parent: int
    element_name: Optional[str] = None
    host_resource: Optional[str] = None         # not read yet: which Disk it holds


@dataclass
class Nic:                                      # ResourceType 10
    resource_subtype: Optional[str] = None
    connection: Optional[str] = None


@dataclass
class VirtualHardware:                          # VirtualHardwareSection
    vcpus: Optional[int] = None
    memory_bytes: Optional[int] = None
    controllers: List[Controller] = field(default_factory=list)
    disk_drives: List[DiskDrive] = field(default_factory=list)
    nics: List[Nic] = field(default_factory=list)
    transport: List[str] = field(default_factory=list)  # not read yet: ovf:transport, split on spaces
    system_type: Optional[str] = None           # not read yet: vssd:VirtualSystemType
    system_identifier: Optional[str] = None     # not read yet: vssd:VirtualSystemIdentifier


@dataclass
class Property:                                 # ProductSection/Property, not read yet
    key: str
    type: str
    user_configurable: bool
    password: bool
    value: Optional[str] = None
    qualifiers: Optional[str] = None
    category: Optional[str] = None              # the Category element before it
    label: Optional[str] = None
    description: Optional[str] = None


@dataclass
class Product:                                  # ProductSection, not read yet
    product_class: Optional[str] = None         # ovf:class
    instance: Optional[str] = None              # ovf:instance
    product: Optional[str] = None
    vendor: Optional[str] = None
    version: Optional[str] = None
    full_version: Optional[str] = None
    product_url: Optional[str] = None
    vendor_url: Optional[str] = None
    app_url: Optional[str] = None
    properties: List[Property] = field(default_factory=list)


@dataclass
class Eula:                                     # EulaSection, not read yet
    license: str


@dataclass
class OperatingSystem:                          # OperatingSystemSection, not read yet
    id: int
    version: Optional[str] = None
    os_type: Optional[str] = None
    description: Optional[str] = None


@dataclass
class DeploymentOption:                         # DeploymentOptionSection/Configuration, not read yet
    id: str
    default: bool
    label: Optional[str] = None
    description: Optional[str] = None


@dataclass
class VirtualSystem:
    id: Optional[str] = None
    name: Optional[str] = None                  # not read yet: VirtualSystem/Name
    description: Optional[str] = None           # not read yet
    hardware: List[VirtualHardware] = field(default_factory=list)  # the parser fills exactly one
    products: List[Product] = field(default_factory=list)          # not read yet
    eulas: List[Eula] = field(default_factory=list)                # not read yet
    operating_system: Optional[OperatingSystem] = None             # not read yet


@dataclass
class Envelope:
    namespace: str                              # the envelope namespace URI
    virtual_system: VirtualSystem
    version: Optional[str] = None               # ovf:version, if stated
    files: List[File] = field(default_factory=list)
    disks: List[Disk] = field(default_factory=list)
    networks: List[Network] = field(default_factory=list)
    deployment_options: List[DeploymentOption] = field(default_factory=list)  # not read yet


@dataclass
class ManifestEntry:
    name: str
    algorithm: str                              # lower case, as today
    digest: str


@dataclass
class Manifest:
    entries: List[ManifestEntry] = field(default_factory=list)  # every line, duplicates included


def to_json(model):
    """Serialise a model as the expected files hold it: sorted keys, and a final newline."""
    return json.dumps(dataclasses.asdict(model), sort_keys=True, indent=2, ensure_ascii=False) + '\n'
