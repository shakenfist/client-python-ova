import click
import humanize
from shakenfist_client import apiclient, util
import re
import sys
import tarfile
import xml.etree.ElementTree as ET


def _emit_debug(ctx, m):
    if ctx.obj['VERBOSE']:
        print(m)


@click.group(help='OVA commands (via the shakenfist-client-ova plugin)')
def ova():
    ...


# Manifest files contain either sha1 or sha256 hashes
#     SHA1 (myvm-disk001.vmdk) = aeb6a6c54fcc579d7a130b5f70faf98b4eab9c07
#     SHA256(disk1.vmdk)= e1a654d69cf4112756899c6d639...c760e2f271146cbf5
MANIFEST_LINE_RE = re.compile(r'^([^ ]+) *\((.*)\) *= *(.*)$')

# https://www.dmtf.org/sites/default/files/standards/documents/DSP0243_1.1.0.pdf
V1_NS = '{http://schemas.dmtf.org/ovf/envelope/1}'

# https://www.dmtf.org/sites/default/files/standards/documents/DSP0243_2.1.1.pdf
V2_NS = '{http://schemas.dmtf.org/ovf/envelope/2}'

VBOX_NS = '{http://www.virtualbox.org/ovf/machine}'


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
                root = ET.fromstring(f.read())
                if root.tag != f'{V1_NS}Envelope':
                    print(f'Unknown root element {root.tag}!')
                    sys.exit(1)

                for child in root:
                    if child.tag == f'{V1_NS}References':
                        for subchild in child.findall(f'{V1_NS}File'):
                            attrs = subchild.attrib
                            id = attrs[f'{V1_NS}id']
                            value = attrs[f'{V1_NS}href']
                            references[id] = value
                        print(f'    References: {references}')

                    elif child.tag == f'{V1_NS}DiskSection':
                        for subchild in child.findall(f'{V1_NS}Disk'):
                            attrs = subchild.attrib

                            disks.append({
                                'id': attrs[f'{V1_NS}diskId'],
                                'capacity': attrs[f'{V1_NS}capacity'],
                                'capacity_allocation_units': attrs.get(f'{V1_NS}capacityAllocationUnits'),
                                'populated_size': attrs.get(f'{V1_NS}populatedSize'),
                                'reference': attrs[f'{V1_NS}fileRef'],
                                'uuid': attrs.get(f'{VBOX_NS}uuid')
                            })
                        print(f'    Disks: {disks}')

                    elif child.tag == f'{V1_NS}NetworkSection':
                        for subchild in child.findall(f'{V1_NS}Network'):
                            attrs = subchild.attrib
                            networks.append(attrs[f'{V1_NS}name'])
                        print(f'    Networks: {networks}')

                    elif child.tag == f'{V1_NS}VirtualSystem':
                        for subchild in child:
                            print(subchild)

                    elif child.tag == f'{V1_NS}VirtualSystemCollection':
                        print('OVAs with VirtualSystemCollection elements are not')
                        print('supported at this time. Please report this!')
                        sys.exit(1)

                    else:
                        print(f'Unhandled XML child element: {child}')
                        print(f'    Attributes: {child.attrib}')
                        print()
                        sys.exit(1)

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

ova.add_command(ova_import)


def load(cli):
    cli.add_command(ova)
