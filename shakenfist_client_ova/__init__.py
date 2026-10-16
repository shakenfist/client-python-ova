import click
import humanize
import math
from shakenfist_client import apiclient, util
import sys
import tarfile

from shakenfist_client_ova import ovf


@click.group(help='OVA commands (via the shakenfist-client-ova plugin)')
def ova():
    ...


def _mib(size):
    mib = size / 1024 / 1024
    if mib == int(mib):
        return '%d' % mib
    return '%.2f' % mib


def _hardware_summary(hardware):
    """The lines describing one VirtualHardware, for the summary and the upload loop."""
    lines = [
        '    vCPUs: %s' % ('not stated' if hardware.vcpus is None else hardware.vcpus),
        '    Memory: %s' % ('not stated' if hardware.memory_bytes is None
                            else '%s MiB' % _mib(hardware.memory_bytes)),
    ]
    for controller in hardware.controllers:
        lines.append('    Controller %s: %s' % (controller.instance_id, controller.bus))
    for nic in hardware.nics:
        lines.append('    NIC: %s on %s' % (nic.resource_subtype, nic.connection))
    for drive in hardware.disk_drives:
        lines.append('    Disk drive: %s at address %d on controller %s'
                     % (drive.element_name, drive.address_on_parent, drive.parent))
    return lines


def _operating_system_summary(operating_system):
    """The line describing the guest operating system: its id, its type and its description."""
    parts = ['id %d' % operating_system.id]
    if operating_system.os_type:
        parts.append('type %s' % operating_system.os_type)
    if operating_system.description:
        parts.append(operating_system.description)
    return '    Operating system: %s' % ', '.join(parts)


def _product_summary(product):
    """The line describing a product by name and version only, or None if it has neither."""
    parts = []
    if product.product:
        parts.append(product.product)
    if product.version:
        parts.append('version %s' % product.version)
    if not parts:
        return None
    return '    Product: %s' % ', '.join(parts)


def _unset_properties(envelope):
    """The properties a user is expected to set that the descriptor gives no value for."""
    return [prop
            for product in envelope.virtual_system.products
            for prop in product.properties
            if prop.user_configurable and not prop.value]


def _envelope_summary(envelope, version, name):
    """The lines describing a parsed descriptor, printed after the parse."""
    lines = [
        '    Version: %s' % version,
        '    System id: %s' % name,
    ]
    if envelope.virtual_system.operating_system is not None:
        lines.append(_operating_system_summary(envelope.virtual_system.operating_system))
    for product in envelope.virtual_system.products:
        line = _product_summary(product)
        if line is not None:
            lines.append(line)
    for file in envelope.files:
        lines.append('    File %s: %s' % (file.id, file.href))
    for disk in envelope.disks:
        lines.append('    Disk %s: %d GiB, file %s, format %s'
                     % (disk.disk_id, math.ceil(disk.capacity_bytes / 1024 ** 3), disk.file_ref, disk.format))
    for network in envelope.networks:
        lines.append('    Network: %s' % network.name)
    lines.extend(_hardware_summary(envelope.virtual_system.hardware[0]))
    return lines


@ova.command(name='import', help='Import an OVA file')
@click.argument('source', type=click.Path(exists=True))
@click.option('--namespace', type=click.STRING,
              help=('If you are an admin, you can import the OVA into a '
                    'different namespace.'))
@click.option('--accept-eula', is_flag=True,
              help=('Accept the licence agreement of an appliance that has one. Without this the '
                    'licence is printed and the import stops.'))
@click.pass_context
def ova_import(ctx, source=None, namespace=None, accept_eula=False):
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

        try:
            element_hashes = {}
            for manifest_file in manifest_files:
                with archive.extractfile(manifest_file) as f:
                    manifest = ovf.parse_manifest(f.read())
                for entry in manifest.entries:
                    element_hashes[entry.name] = (entry.algorithm, entry.digest)
                    if entry.name in disk_files:
                        disk_files[entry.name]['hash'] = (entry.algorithm, entry.digest)

            # A second descriptor replaces the first, as it always has.
            # Checking the archive will refuse it instead; see
            # docs/plans/PLAN-ovf-parser.md.
            for ovf_file in ovf_files:
                with archive.extractfile(ovf_file) as f:
                    envelope = ovf.parse_descriptor(f.read())

                version = envelope.version
                if version is None:
                    version = 1
                name = envelope.virtual_system.id
                if name is None:
                    name = 'Imported OVA VM'
                hardware = envelope.virtual_system.hardware[0]

                print('VM description:')
                for line in _envelope_summary(envelope, version, name):
                    print(line)

                eulas = envelope.virtual_system.eulas
                for eula in eulas:
                    print()
                    print('Licence agreement:')
                    print(eula.license)
                if eulas and not accept_eula:
                    print()
                    print('This appliance has a licence agreement, printed above. '
                          'Re-run with --accept-eula to accept it.')
                    sys.exit(1)

                unset = _unset_properties(envelope)
                if unset:
                    print()
                    print('Warning: this appliance expects the following properties to be set at first boot, '
                          'and Shaken Fist cannot deliver them yet:')
                    for prop in unset:
                        print('    %s' % (prop.key if not prop.label else '%s (%s)' % (prop.key, prop.label)))
        except ovf.OVFError as e:
            print(str(e))
            sys.exit(1)

        print()
        print('Uploading disk images...')
        print()

        for disk_file in disk_files:
            ti = archive.getmember(disk_file)
            disk_files[disk_file]['size'] = ti.size

            print(f'{disk_file} with size '
                  f'{humanize.naturalsize(disk_files[disk_file]["size"])}')
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
            for line in _hardware_summary(hardware):
                print(line)
            print()


ova.add_command(ova_import)


def load(cli):
    cli.add_command(ova)
