"""What the OVF parser returns: plain dataclasses, and their one serialisation.

Lists keep document order. Sizes are integers in bytes; any conversion to MiB
or GiB is the command's. Each class lists its required fields first, because a
dataclass refuses a field without a default after one with a default; to_json
sorts keys, so the order never reaches an expected file.

A field that is not Optional always holds a value: the parser refuses a
descriptor that does not give it. The converse does not hold: an Optional
field may still always be filled, as VirtualSystem.id is, and its comment then
says so. An element's text is stripped of surrounding whitespace, and empty
text is None; an attribute's value is kept as written.
"""

import dataclasses
from dataclasses import dataclass, field
import json
from typing import List, Optional


@dataclass
class File:                                     # References/File
    id: str
    href: str
    size: Optional[int] = None                  # ovf:size
    compression: Optional[str] = None           # ovf:compression, such as 'gzip'
    chunk_size: Optional[int] = None            # ovf:chunkSize


@dataclass
class Disk:                                     # DiskSection/Disk
    disk_id: str
    capacity_bytes: int                         # ovf:capacity x its allocation units
    file_ref: Optional[str] = None
    format: Optional[str] = None
    populated_size: Optional[int] = None        # ovf:populatedSize
    parent_ref: Optional[str] = None            # ovf:parentRef: the diskId of a delta disk's parent
    interface: Optional[str] = None             # never filled: oVirt's ovf:disk-interface, for an oVirt reader
    # The disk the producer marks as the boot disk, from the non-standard
    # ovf:boot, which the specification does not define. None means the
    # descriptor does not say.
    boot: Optional[bool] = None


@dataclass
class Network:                                  # NetworkSection/Network
    name: str
    description: Optional[str] = None


@dataclass
class Controller:                               # ResourceType 5 and 6, and 20 with a SATA or NVMe subtype
    instance_id: str
    bus: str                                    # 'ide', 'scsi', 'sata' or 'nvme'


@dataclass
class DiskDrive:                                # ResourceType 17
    parent: str                                 # the controller's instance_id
    address_on_parent: int
    element_name: Optional[str] = None
    host_resource: Optional[str] = None         # which Disk it holds, such as 'ovf:/disk/vmdisk1'


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
    transport: List[str] = field(default_factory=list)  # ovf:transport, split on spaces
    system_type: Optional[str] = None           # vssd:VirtualSystemType
    system_identifier: Optional[str] = None     # vssd:VirtualSystemIdentifier


@dataclass
class Property:                                 # ProductSection/Property, in the default configuration
    key: str
    type: str
    user_configurable: bool
    password: bool
    value: Optional[str] = None                 # ovf:value, or the Value child for the default configuration
    qualifiers: Optional[str] = None
    category: Optional[str] = None              # the Category element before it
    label: Optional[str] = None
    description: Optional[str] = None


@dataclass
class Product:                                  # ProductSection
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
class Eula:                                     # EulaSection
    license: str


@dataclass
class OperatingSystem:                          # OperatingSystemSection
    id: int
    version: Optional[str] = None
    os_type: Optional[str] = None               # ovf:osType, or VMware's vmw:osType
    description: Optional[str] = None


@dataclass
class DeploymentOption:                         # DeploymentOptionSection/Configuration
    id: str
    default: bool                               # true for the one configuration the parser builds
    label: Optional[str] = None
    description: Optional[str] = None


@dataclass
class VirtualSystem:
    id: Optional[str] = None                    # ovf:id: the parser always fills it, as the attribute is required
    name: Optional[str] = None                  # VirtualSystem/Name
    description: Optional[str] = None           # VirtualSystem/Description
    hardware: List[VirtualHardware] = field(default_factory=list)  # every VirtualHardwareSection; at least one
    products: List[Product] = field(default_factory=list)
    eulas: List[Eula] = field(default_factory=list)
    operating_system: Optional[OperatingSystem] = None


@dataclass
class Envelope:
    namespace: str                              # the envelope namespace URI
    virtual_system: VirtualSystem
    version: Optional[str] = None               # ovf:version, if stated
    files: List[File] = field(default_factory=list)
    disks: List[Disk] = field(default_factory=list)
    networks: List[Network] = field(default_factory=list)
    deployment_options: List[DeploymentOption] = field(default_factory=list)


@dataclass
class ManifestEntry:
    name: str
    algorithm: str                              # lower case, whatever case the manifest used
    digest: str


@dataclass
class Manifest:
    entries: List[ManifestEntry] = field(default_factory=list)  # every entry, in the manifest's order


def to_json(model):
    """Serialise a model as the expected files hold it: sorted keys, and a final newline."""
    return json.dumps(dataclasses.asdict(model), sort_keys=True, indent=2, ensure_ascii=False) + '\n'
