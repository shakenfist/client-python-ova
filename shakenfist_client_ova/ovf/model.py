"""What the OVF parser returns: plain dataclasses, and their one serialisation.

Lists keep document order. Sizes are integers in bytes; any conversion to MiB
or GiB is the command's. Fields marked "phase 3" are not yet filled, and hold
None or an empty list. Each class lists its required fields first, because a
dataclass refuses a field without a default after one with a default; to_json
sorts keys, so the order never reaches an expected file.
"""

import dataclasses
from dataclasses import dataclass, field
import json
from typing import List, Optional


@dataclass
class File:                                     # References/File
    id: str
    href: str
    size: Optional[int] = None                  # phase 3; phase 4 checks it
    compression: Optional[str] = None           # phase 3; phase 4 refuses gzip
    chunk_size: Optional[int] = None            # phase 3; phase 4 refuses it


@dataclass
class Disk:                                     # DiskSection/Disk
    disk_id: str
    capacity_bytes: int                         # ovf:capacity x its allocation units
    file_ref: Optional[str] = None
    format: Optional[str] = None
    populated_size: Optional[int] = None        # phase 3
    interface: Optional[str] = None             # phase 3, master open question 4


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
    host_resource: Optional[str] = None         # phase 3: which Disk it holds


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
    transport: List[str] = field(default_factory=list)  # phase 3: ovf:transport, split on spaces
    system_type: Optional[str] = None           # phase 3: vssd:VirtualSystemType
    system_identifier: Optional[str] = None     # phase 3: vssd:VirtualSystemIdentifier


@dataclass
class Property:                                 # ProductSection/Property, phase 3
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
class Product:                                  # ProductSection, phase 3
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
class Eula:                                     # EulaSection, phase 3
    license: str


@dataclass
class OperatingSystem:                          # OperatingSystemSection, phase 3
    id: int
    version: Optional[str] = None
    os_type: Optional[str] = None
    description: Optional[str] = None


@dataclass
class DeploymentOption:                         # DeploymentOptionSection/Configuration, phase 3
    id: str
    default: bool
    label: Optional[str] = None
    description: Optional[str] = None


@dataclass
class VirtualSystem:
    id: Optional[str] = None
    name: Optional[str] = None                  # phase 3: VirtualSystem/Name
    description: Optional[str] = None           # phase 3
    hardware: List[VirtualHardware] = field(default_factory=list)  # phase 2 fills exactly one
    products: List[Product] = field(default_factory=list)          # phase 3
    eulas: List[Eula] = field(default_factory=list)                # phase 3
    operating_system: Optional[OperatingSystem] = None             # phase 3


@dataclass
class Envelope:
    namespace: str                              # the envelope namespace URI
    virtual_system: VirtualSystem
    version: Optional[str] = None               # ovf:version, if stated
    files: List[File] = field(default_factory=list)
    disks: List[Disk] = field(default_factory=list)
    networks: List[Network] = field(default_factory=list)
    deployment_options: List[DeploymentOption] = field(default_factory=list)  # phase 3


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
