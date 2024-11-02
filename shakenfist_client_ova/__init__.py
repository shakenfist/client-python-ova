import click
import dpath
import humanize
import json
import math
import re
from shakenfist_client import apiclient, util
import sys
import tarfile
import xmltodict


@click.group(help='OVA commands (via the shakenfist-client-ova plugin)')
def ova():
    ...


# Manifest files contain either sha1 or sha256 hashes
#     SHA1 (myvm-disk001.vmdk) = aeb6a6c54fcc579d7a130b5f70faf98b4eab9c07
#     SHA256(disk1.vmdk)= e1a654d69cf4112756899c6d639...c760e2f271146cbf5
MANIFEST_LINE_RE = re.compile(r'^([^ ]+) *\((.*)\) *= *(.*)$')

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
        return 2 ^ int(m.group(1))
    elif element[key] == 'MegaBytes':
        return 1024 * 1024
    elif element[key] == 'GigaBytes':
        return 1024 * 1024 * 1024
    else:
        print(f'Unknown allocation unit: "{element[key]}"')
        print(element)
        sys.exit(1)


dpath.options.ALLOW_EMPTY_STRING_KEYS = True


def _coerce_to_list(input):
    if isinstance(input, list):
        return input
    elif isinstance(input, dict):
        return [input]


def _delete_if_empty(input, path):
    if not dpath.get(input, path):
        dpath.delete(input, path)


@ova.command(name='import', help='Import an OVA file')
@click.argument('source', type=click.Path(exists=True))
@click.option('--namespace', type=click.STRING,
              help=('If you are an admin, you can import the OVA into a '
                    'different namespace.'))
@click.pass_context
def ova_import(ctx, source=None, namespace=None):
    ctx.obj['namespace'] = namespace
    ctx.obj['CLIENT'] = apiclient.Client(
        async_strategy=apiclient.ASYNC_CONTINUE, namespace=namespace)

    ovf_files = []
    disk_files = {}
    manifest_files = []
    other_files = []

    with tarfile.open(source) as archive:
        for name in archive.getnames():
            if name.endswith('.ovf'):
                ovf_files.append(name)
            elif name.endswith('.vmdk'):
                disk_files[name] = {}
            elif name.endswith('.mf'):
                manifest_files.append(name)
            else:
                other_files.append(name)

        print('Detected archive members:')
        print('    OVF:      %s' % ', '.join(ovf_files))
        print('    Disk:     %s' % ', '.join(disk_files.keys()))
        print('    Manifest: %s' % ', '.join(manifest_files))
        print('    Other:    %s' % ', '.join(other_files))
        print()

        print('Loading element hashes')
        element_hashes = {}
        for manifest_file in manifest_files:
            with archive.extractfile(manifest_file) as f:
                for line in f.read().decode().split('\n'):
                    if not line:
                        continue

                    m = MANIFEST_LINE_RE.match(line)
                    if m:
                        alg = m.group(1).lower()
                        filename = m.group(2)
                        hash = m.group(3)
                        element_hashes[filename] = (alg, hash)
                        if filename in disk_files:
                            disk_files[filename]['hash'] = (alg, hash)
                    else:
                        print(f'Failed to parse manifest line: {line}')
                        sys.exit(1)

        print('Loading VM description')
        references = {}
        disks = []
        networks = []

        for ovf_file in ovf_files:
            with archive.extractfile(ovf_file) as f:
                ovf = xmltodict.parse(
                    f.read(), process_namespaces=True, namespaces=NAMESPACES)

                # Strip meaningless info tags
                print(f'    Removed {dpath.delete(ovf, "**/v1:Info")} unused '
                      'info keys')

                try:
                    version = dpath.get(ovf, ['v1:Envelope', '@v1:version'])
                    dpath.delete(ovf, ['v1:Envelope', '@v1:version'])
                    print(f'    Version: {version}')
                except KeyError:
                    print('    No detected version, assuming v1')
                    version = 1

                try:
                    name = dpath.get(
                        ovf, ['v1:Envelope', 'v1:VirtualSystem', '@v1:id'])
                    dpath.delete(
                        ovf, ['v1:Envelope', 'v1:VirtualSystem', '@v1:id'])
                    print(f'    Name: {name}')
                except KeyError:
                    print('    No detected name, using something generic')
                    name = 'Imported OVA VM'

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
                files = _coerce_to_list(dpath.get(
                    ovf, ['v1:Envelope', 'v1:References', 'v1:File']))
                for file in files:
                    references[file['@v1:id']] = file['@v1:href']
                print(f'    References: {references}')
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
                disks = _coerce_to_list(dpath.get(
                    ovf, ['v1:Envelope', 'v1:DiskSection', 'v1:Disk']))
                print(f'    Disks:')
                for disk in disks:
                    alloc = _parse_alloc_units_to_bytes(disk)
                    disk['capacity_gb'] = math.ceil(
                        int(disk['@v1:capacity']) * alloc / 1024 / 1024 / 1024)
                    print('        %s' % disk)
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
                networks = _coerce_to_list(dpath.get(
                    ovf, ['v1:Envelope', 'v1:NetworkSection', 'v1:Network']))
                print(f'    Networks:')
                for network in networks:
                    print('        %s' % network)
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
                hardware = {
                    'disks': {},
                    'interfaces': [],
                    'has_ide': False,
                    'has_sata': False,
                    'has_scsi': False
                }
                storage_controllers_by_id = {}

                elements = _coerce_to_list(dpath.get(
                    ovf, ['v1:Envelope', 'v1:VirtualSystem',
                          'v1:VirtualHardwareSection', 'v1:Item']))
                for element in elements:
                    if element['rasd:ResourceType'] == '1':
                        # "Other", thanks guys...
                        if element.get('@v1:required', 'true') != 'false':
                            print(f'    Unhandled "other" element: {element}')
                            sys.exit(1)
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
                        print(f'    Memory: {element}')
                    elif element['rasd:ResourceType'] == '5':
                        # IDE controllers
                        hardware['has_ide'] = True
                        storage_controllers_by_id[element['rasd:InstanceID']] = \
                            'ide'
                    elif element['rasd:ResourceType'] == '6':
                        # SCSI controllers
                        hardware['has_scsi'] = True
                        storage_controllers_by_id[element['rasd:InstanceID']] = \
                            'scsi'
                    elif element['rasd:ResourceType'] == '10':
                        # Network interfaces
                        hardware['interfaces'].append((
                            element['rasd:ResourceSubType'],
                            element['rasd:Connection']))
                    elif element['rasd:ResourceType'] == '17':
                        # Disks
                        bus = storage_controllers_by_id[element['rasd:Parent']]
                        hardware['disks'][int(element['rasd:AddressOnParent'])] = \
                            (bus, element['rasd:ElementName'])
                    elif element['rasd:ResourceType'] == '20':
                        # Other storage controller
                        if element['rasd:ResourceSubType'] == 'AHCI':
                            hardware['has_sata'] = True
                            storage_controllers_by_id[element['rasd:InstanceID']] = \
                                'sata'
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
                        print(f'    Unknown hardware element: {element}')
                        sys.exit(1)

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
                    print()
                    print('Not all of the OVF file was parsed!')
                    print()
                    print(json.dumps(ovf, sort_keys=True, indent=4))
                    sys.exit(1)

        print()
        print('Uploading disk images...')
        print()

        for disk_file in disk_files:
            ti = archive.getmember(disk_file)
            disk_files[disk_file]['size'] = ti.size

            print(f'{disk_file} with size '
                  f'{humanize.naturalsize(disk_files[disk_file]['size'])}')
            source_url = f'ova://{source}/{disk_file}'
            if not ctx.obj['CLIENT'].check_capability('blob-search-by-hash'):
                blob = None
            else:
                with archive.extractfile(disk_file) as f:
                    blob = util.checksum_with_progress_from_file_like_object(
                        ctx.obj['CLIENT'], f, disk_files[disk_file]['size'])

            if not blob:
                with archive.extractfile(disk_file) as f:
                    artifact = util.upload_artifact_with_progress_file_like_object(
                        ctx.obj['CLIENT'], name, f, disk_files[disk_file]['size'],
                        source_url)
            else:
                print('Disk is already present in the cluster')
                artifact = ctx.obj['CLIENT'].blob_artifact(
                    name, blob['uuid'], source_url=source_url)

            print('Disk artifact is %s' % artifact['uuid'])
            disk_files[disk_file]['artifact'] = artifact

            print()
            print(hardware)
            print()

ova.add_command(ova_import)


def load(cli):
    cli.add_command(ova)
