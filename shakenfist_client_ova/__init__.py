import click
import humanize
import json
from shakenfist_client import apiclient, util
import re
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
}

STREAM_OPTIMIZED = ('http://www.vmware.com/interfaces/specifications/'
                    'vmdk.html#streamOptimized')


def dpath(top, path):
    d = top
    for elem in path:
        d = d.get(elem)
        if not d:
            return None

    return d


def dfind(d, tag, path=[]):
    if tag in d:
        return path
    for elem in d:
        if isinstance(d[elem], dict):
            for found in dfind(d[elem], tag, path + [elem]):
                yield found


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
                for info_tag in dfind(ovf, 'v1:Info'):
                    print(info_tag)
                    del ovf['v1:Envelope']['v1:NetworkSection']['v1:Info']
                sys.exit(1)

                version = ovf['v1:Envelope']['@v1:version']
                del ovf['v1:Envelope']['@v1:version']
                print(f'    Version: {version}')

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
                files = dpath(ovf, ['v1:Envelope', 'v1:References', 'v1:File'])
                if files:
                    if isinstance(files, list):
                        for file in files:
                            references[file['@v1:id']] = file['@v1:href']
                    elif isinstance(files, dict):
                        references[files['@v1:id']] = files['@v1:href']
                    else:
                        print(
                            f'Unknown type for file references ({type(files)})')
                        sys.exit(1)

                    print(f'    References: {references}')
                    del ovf['v1:Envelope']['v1:References']['v1:File']
                    if not ovf['v1:Envelope']['v1:References']:
                        del ovf['v1:Envelope']['v1:References']

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
                disks = dpath(
                    ovf, ['v1:Envelope', 'v1:DiskSection', 'v1:Disk'])
                if disks:
                    if isinstance(disks, dict):
                        disks[disks]

                    print(f'    Disks:')
                    for disk in disks:
                        print('        %s' % disk)
                    del ovf['v1:Envelope']['v1:DiskSection']['v1:Disk']
                    if 'v1:Info' in ovf['v1:Envelope']['v1:DiskSection']:
                        del ovf['v1:Envelope']['v1:DiskSection']['v1:Info']
                    if not ovf['v1:Envelope']['v1:DiskSection']:
                        del ovf['v1:Envelope']['v1:DiskSection']

                # "v1:NetworkSection": {
                #     "v1:Info": "Logical networks used in the package",
                #     "v1:Network": {
                #         "@v1:name": "NAT",
                #         "v1:Description": "Logical network used by this appliance."
                #     }
                # },
                networks = dpath(
                    ovf, ['v1:Envelope', 'v1:NetworkSection', 'v1:Network'])
                if networks:
                    if isinstance(networks, dict):
                        networks = [networks]

                    print(f'    Networks:')
                    for network in networks:
                        print('        %s' % network)
                    del ovf['v1:Envelope']['v1:NetworkSection']['v1:Network']
                    if not ovf['v1:Envelope']['v1:NetworkSection']:
                        del ovf['v1:Envelope']['v1:NetworkSection']

                # Remove envelope if empty
                if not ovf['v1:Envelope']:
                    del ovf['v1:Envelope']

                # Remove boiler plate
                for bp in ['@xml:lang', '@xmlns']:
                    if bp in ovf['v1:Envelope']:
                        del ovf['v1:Envelope'][bp]

                # If there is anything left, it means we haven't parsed everything
                if ovf:
                    print()
                    print('Not all of the OVF file was parsed!')
                    print()
                    print(json.dumps(ovf, sort_keys=True, indent=4))
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
