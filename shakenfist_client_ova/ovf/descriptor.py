"""The descriptor parser.

This is the import command's descriptor walk, moved here from the command
without changing what it accepts: every dpath call, every deletion and its
order are as they were. It exists only until the parser moves to ElementTree
(see docs/plans/PLAN-ovf-parser.md), which replaces all of it, so it is moved
faithfully rather than tidied.

The walk parses by consumption. Each section it understands is deleted from
the parsed descriptor as it is read, and anything left at the end is refused.
The model is built at the end, from what the walk read.
"""

import json
import math
import re
from xml.parsers.expat import ExpatError

import dpath
import xmltodict

from .errors import (
    EntityDeclarationError, MalformedDescriptorError, OVFError, UnknownAllocationUnitError, UnparsedContentError,
    UnsupportedDescriptorError, UnsupportedHardwareError)
from .model import Controller, Disk, DiskDrive, Envelope, File, Network, Nic, VirtualHardware, VirtualSystem


NAMESPACES = {
    # https://www.w3.org/XML/1998/namespace
    'http://www.w3.org/XML/1998/namespace': 'xml',

    # https://www.dmtf.org/sites/default/files/standards/documents/DSP0243_1.1.0.pdf
    'http://schemas.dmtf.org/ovf/envelope/1': 'v1',

    # https://www.dmtf.org/sites/default/files/standards/documents/DSP0243_2.1.1.pdf
    'http://schemas.dmtf.org/ovf/envelope/2': 'v2',

    # I cannot find documentation for these
    'http://www.virtualbox.org/ovf/machine': 'vbox',
    ('http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/'
     'CIM_ResourceAllocationSettingData'): 'rasd',
    ('http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/'
     'CIM_VirtualSystemSettingData'): 'vssd',
    'http://www.vmware.com/schema/ovf': 'vmware'
}

# The walk reads only v1: elements, so a descriptor it accepts is always in
# this namespace.
ENVELOPE_V1_NAMESPACE = 'http://schemas.dmtf.org/ovf/envelope/1'

STREAM_OPTIMIZED = ('http://www.vmware.com/interfaces/specifications/'
                    'vmdk.html#streamOptimized')

BYTE_MATHS_ALLOCATION_UNITS_RE = re.compile(r'^byte \* 2\^([0-9]+)$')


def _parse_alloc_units_to_bytes(element):
    if 'rasd:AllocationUnits' in element:
        key = 'rasd:AllocationUnits'
    elif '@v1:capacityAllocationUnits' in element:
        key = '@v1:capacityAllocationUnits'
    else:
        return 1

    m = BYTE_MATHS_ALLOCATION_UNITS_RE.match(element[key])
    if m:
        return 2 ** int(m.group(1))
    elif element[key] == 'MegaBytes':
        return 1024 * 1024
    elif element[key] == 'GigaBytes':
        return 1024 * 1024 * 1024
    else:
        raise UnknownAllocationUnitError(f'Unknown allocation unit: "{element[key]}"\n{element}')


dpath.options.ALLOW_EMPTY_STRING_KEYS = True


def _coerce_to_list(input):
    if isinstance(input, list):
        return input
    elif isinstance(input, dict):
        return [input]


def _delete_if_empty(input, path):
    if not dpath.get(input, path):
        dpath.delete(input, path)


def _get(element, key):
    """An optional value from an xmltodict element, for building the model only.

    The walk reads nothing through this, so it refuses nothing the walk accepts.
    An element that carries attributes is a dict, whose text is under '#text'.
    """
    if not isinstance(element, dict):
        return None
    return _text(element.get(key))


def _text(value):
    if isinstance(value, dict):
        return value.get('#text')
    return value


def _parse(data):
    try:
        ovf = xmltodict.parse(
            data, process_namespaces=True, namespaces=NAMESPACES)
    except ExpatError as e:
        raise MalformedDescriptorError(f'The descriptor is not well-formed XML: {e}') from None
    except ValueError as e:
        # xmltodict refuses an entity declaration with ValueError('entities are
        # disabled'), and this matches exactly that message. Any other ValueError
        # is not that refusal, and is left to parse_descriptor to report as an
        # unsupported descriptor. The xmltodict version is pinned in
        # tools/pinned-requirements.txt, so a reworded message shows up as a
        # reviewed golden-file change rather than as a silent mismatch.
        if str(e) != 'entities are disabled':
            raise
        raise EntityDeclarationError(f'The descriptor declares an entity, which is refused: {e}') from None

    # Strip meaningless info tags
    dpath.delete(ovf, '**/v1:Info')

    try:
        version = dpath.get(ovf, ['v1:Envelope', '@v1:version'])
        dpath.delete(ovf, ['v1:Envelope', '@v1:version'])
    except KeyError:
        version = None

    try:
        name = dpath.get(
            ovf, ['v1:Envelope', 'v1:VirtualSystem', '@v1:id'])
        dpath.delete(
            ovf, ['v1:Envelope', 'v1:VirtualSystem', '@v1:id'])
    except KeyError:
        name = None

    # Some keys we don't care about
    for ignore in ['DeploymentOptionSection']:
        try:
            dpath.delete(
                ovf, ['v1:Envelope', f'v1:{ignore}'])
        except dpath.exceptions.PathNotFound:
            ...
    for ignore in ['AnnotationSection', 'OperatingSystemSection',
                   'ProductSection']:
        try:
            dpath.delete(
                ovf, ['v1:Envelope', 'v1:VirtualSystem', f'v1:{ignore}'])
        except dpath.exceptions.PathNotFound:
            ...

    # "v1:References": {
    #     "v1:File": {
    #         "@v1:href": "CSE-LABVM-disk001.vmdk",
    #         "@v1:id": "file1"
    #     }
    # },
    #
    # "v1:References": {
    #     "v1:File": [
    #         {
    #             "@v1:href": "CyberOps Workstation-disk001.vmdk",
    #             "@v1:id": "file1"
    #         },
    #         {
    #             "@v1:href": "CyberOps Workstation-disk002.vmdk",
    #             "@v1:id": "file2"
    #         }
    #     ]
    # },
    model_files = []
    files = _coerce_to_list(dpath.get(
        ovf, ['v1:Envelope', 'v1:References', 'v1:File']))
    for file in files:
        # Today's references[file['@v1:id']] = file['@v1:href'] read the href
        # first, so a File missing both still fails naming the href.
        model_files.append(File(href=file['@v1:href'], id=file['@v1:id']))
    dpath.delete(ovf, ['v1:Envelope', 'v1:References', 'v1:File'])
    _delete_if_empty(ovf, ['v1:Envelope', 'v1:References'])

    # "v1:DiskSection": {
    #     "v1:Disk": [
    #         {
    #             "@v1:capacity": "10737418240",
    #             "@v1:diskId": "vmdisk1",
    #             "@v1:fileRef": "file1",
    #             "@v1:format": STREAM_OPTIMIZED,
    #             "@vbox:uuid": "4ef5671e-51fc-450d-9804-8361fb2ec5d9"
    #         },
    #         {
    #             "@v1:capacity": "1073741824",
    #             "@v1:diskId": "vmdisk2",
    #             "@v1:fileRef": "file2",
    #             "@v1:format": STREAM_OPTIMIZED,
    #             "@vbox:uuid": "92052b2b-47c2-43c3-b1a9-520400129e5a"
    #         }
    #     ],
    #     "v1:Info": "List of the virtual disks used in the package"
    # },
    model_disks = []
    disks = _coerce_to_list(dpath.get(
        ovf, ['v1:Envelope', 'v1:DiskSection', 'v1:Disk']))
    for disk in disks:
        alloc = _parse_alloc_units_to_bytes(disk)
        disk['capacity_gb'] = math.ceil(
            int(disk['@v1:capacity']) * alloc / 1024 / 1024 / 1024)
        model_disks.append(Disk(
            disk_id=_get(disk, '@v1:diskId'), capacity_bytes=int(disk['@v1:capacity']) * alloc,
            file_ref=_get(disk, '@v1:fileRef'), format=_get(disk, '@v1:format')))
    dpath.delete(
        ovf, ['v1:Envelope', 'v1:DiskSection', 'v1:Disk'])
    _delete_if_empty(
        ovf, ['v1:Envelope', 'v1:DiskSection'])

    # "v1:NetworkSection": {
    #     "v1:Info": "Logical networks used in the package",
    #     "v1:Network": {
    #         "@v1:name": "NAT",
    #         "v1:Description": "Logical network used by this appliance."
    #     }
    # },
    model_networks = []
    networks = _coerce_to_list(dpath.get(
        ovf, ['v1:Envelope', 'v1:NetworkSection', 'v1:Network']))
    for network in networks:
        model_networks.append(Network(
            name=_get(network, '@v1:name'), description=_get(network, 'v1:Description')))
    dpath.delete(
        ovf, ['v1:Envelope', 'v1:NetworkSection', 'v1:Network'])
    _delete_if_empty(ovf, ['v1:Envelope', 'v1:NetworkSection'])

    # Machine hardware description. Valid resource types appear to
    # be (https://schemas.dmtf.org/wbem/cim-html/2/CIM_ResourceAllocationSettingData.html):
    #    1: Other
    #    2: Computer System
    #    3: Processor
    #    4: Memory
    #    5: IDE Controller
    #    6: Parallel SCSI HBA
    #    7: FC HBA
    #    8: iSCSI HBA
    #    9: IB HCA
    #    10: Ethernet Adapter
    #    11: Other Network Adapter
    #    12: I/O Slot
    #    13: I/O Device
    #    14: Floppy Drive
    #    15: CD Drive
    #    16: DVD drive
    #    17: Disk Drive
    #    18: Tape Drive
    #    19: Storage Extent
    #    20: Other storage device
    #    21: Serial port
    #    22: Parallel port
    #    23: USB Controller
    #    24: Graphics controller
    #    25: IEEE 1394 Controller
    #    26: Partitionable Unit
    #    27: Base Partitionable Unit
    #    28: Power
    #    29: Cooling Capacity
    #    30: Ethernet Switch Port
    #    31: Logical Disk
    #    32: Storage Volume
    #    33: Ethernet Connection
    #    ...
    #    35: Sound card
    #
    # The hardware dictionary and storage_controllers_by_id are today's, kept
    # because how they fail is part of what the walk refuses. The model lists
    # beside them keep every item in document order, where the dictionaries
    # keep the last item for a repeated key.
    hardware = {
        'disks': {},
        'interfaces': [],
        'has_ide': False,
        'has_sata': False,
        'has_scsi': False
    }
    storage_controllers_by_id = {}
    memory_bytes = None
    model_controllers = []
    model_disk_drives = []
    model_nics = []

    elements = _coerce_to_list(dpath.get(
        ovf, ['v1:Envelope', 'v1:VirtualSystem',
              'v1:VirtualHardwareSection', 'v1:Item']))
    for element in elements:
        if element['rasd:ResourceType'] == '1':
            # "Other", thanks guys...
            if element.get('@v1:required', 'true') != 'false':
                raise UnsupportedHardwareError(f'    Unhandled "other" element: {element}')
        elif element['rasd:ResourceType'] == '3':
            # vCPUs
            hardware['vcpus'] = element['rasd:VirtualQuantity']
        elif element['rasd:ResourceType'] == '4':
            # RAM, with allocation units
            alloc = _parse_alloc_units_to_bytes(element)
            hardware['memory_mb'] = (
                int(element['rasd:VirtualQuantity'])
                * alloc / 1024 / 1024)

            element['capacity_mb'] = hardware['memory_mb']
            element['capacity_alloc'] = alloc
            memory_bytes = int(element['rasd:VirtualQuantity']) * alloc
        elif element['rasd:ResourceType'] == '5':
            # IDE controllers
            hardware['has_ide'] = True
            storage_controllers_by_id[element['rasd:InstanceID']] = \
                'ide'
            model_controllers.append(Controller(instance_id=_text(element['rasd:InstanceID']), bus='ide'))
        elif element['rasd:ResourceType'] == '6':
            # SCSI controllers
            hardware['has_scsi'] = True
            storage_controllers_by_id[element['rasd:InstanceID']] = \
                'scsi'
            model_controllers.append(Controller(instance_id=_text(element['rasd:InstanceID']), bus='scsi'))
        elif element['rasd:ResourceType'] == '10':
            # Network interfaces
            hardware['interfaces'].append((
                element['rasd:ResourceSubType'],
                element['rasd:Connection']))
            model_nics.append(Nic(
                resource_subtype=_text(element['rasd:ResourceSubType']),
                connection=_text(element['rasd:Connection'])))
        elif element['rasd:ResourceType'] == '17':
            # Disks
            bus = storage_controllers_by_id[element['rasd:Parent']]
            hardware['disks'][int(element['rasd:AddressOnParent'])] = \
                (bus, element['rasd:ElementName'])
            model_disk_drives.append(DiskDrive(
                parent=_text(element['rasd:Parent']), address_on_parent=int(element['rasd:AddressOnParent']),
                element_name=_text(element['rasd:ElementName'])))
        elif element['rasd:ResourceType'] == '20':
            # Other storage controller
            if element['rasd:ResourceSubType'] == 'AHCI':
                hardware['has_sata'] = True
                storage_controllers_by_id[element['rasd:InstanceID']] = \
                    'sata'
                model_controllers.append(Controller(instance_id=_text(element['rasd:InstanceID']), bus='sata'))
        elif element['rasd:ResourceType'] in [
                '14', '15', '23', '24', '35']:
            # 14: Floppy drives
            # 15: CD ROM drives
            # 23: USB controllers
            # 24: Video cards
            # 35: Sound cards
            # ... all of which we ignore
            ...
        else:
            raise UnsupportedHardwareError(f'    Unknown hardware element: {element}')

    dpath.delete(
        ovf, ['v1:Envelope', 'v1:VirtualSystem',
              'v1:VirtualHardwareSection', 'v1:Item'])

    # These two paths don't have anything useful to us
    dpath.delete(
        ovf, ['v1:Envelope', 'v1:VirtualSystem',
              'v1:VirtualHardwareSection', 'v1:System'])

    try:
        dpath.delete(
            ovf, ['v1:Envelope', 'v1:VirtualSystem',
                  'vbox:Machine'])
    except dpath.exceptions.PathNotFound:
        ...

    # VMWare specific keys we don't translate
    for vhs_key in ['vmware:Config', '@v1:required',
                    '@v1:transport']:
        try:
            dpath.delete(
                ovf, ['v1:Envelope', 'v1:VirtualSystem',
                      'v1:VirtualHardwareSection', vhs_key])
        except dpath.exceptions.PathNotFound:
            ...
    for env_key in ['@vmware:buildId', 'vmware:IpAssignmentSection']:
        try:
            dpath.delete(ovf, ['v1:Envelope', env_key])
        except dpath.exceptions.PathNotFound:
            ...

    try:
        dpath.delete(ovf, ['v1:Envelope', 'v1:VirtualSystem',
                           'v1:Name'])
    except dpath.exceptions.PathNotFound:
        ...

    _delete_if_empty(
        ovf, ['v1:Envelope', 'v1:VirtualSystem',
              'v1:VirtualHardwareSection'])
    _delete_if_empty(
        ovf, ['v1:Envelope', 'v1:VirtualSystem'])

    # Remove boiler plate
    for bp in ['@xml:lang', '@xmlns']:
        if bp in ovf['v1:Envelope']:
            del ovf['v1:Envelope'][bp]

    # Remove envelope if empty
    _delete_if_empty(ovf, ['v1:Envelope'])

    # If there is anything left, it means we haven't parsed everything
    if ovf:
        raise UnparsedContentError(
            'Not all of the OVF file was parsed!\n\n' + json.dumps(ovf, sort_keys=True, indent=4))

    vcpus = hardware.get('vcpus')
    return Envelope(
        namespace=ENVELOPE_V1_NAMESPACE,
        version=version,
        files=model_files,
        disks=model_disks,
        networks=model_networks,
        virtual_system=VirtualSystem(
            id=name,
            hardware=[VirtualHardware(
                vcpus=int(_text(vcpus)) if vcpus is not None else None,
                memory_bytes=memory_bytes,
                controllers=model_controllers,
                disk_drives=model_disk_drives,
                nics=model_nics)]))


def parse_descriptor(data):
    """Parse a descriptor's bytes into an Envelope.

    Raises an OVFError subclass for every failure. A failure the parser does
    not yet name is an UnsupportedDescriptorError, raised from the original
    exception.
    """
    try:
        return _parse(data)
    except OVFError:
        raise
    except Exception as e:
        raise UnsupportedDescriptorError(
            'Could not parse the descriptor: %s: %s' % (type(e).__name__, e)) from e
