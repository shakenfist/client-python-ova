import click
import humanize
import json
import math
import os
from shakenfist_client import apiclient, util
import sys
from tqdm import tqdm
import unicodedata

from shakenfist_client_ova import ovf


@click.group(help='OVA commands (via the shakenfist-client-ova plugin)')
def ova():
    ...


def _printable(text):
    """Text from the OVA made safe to print to a terminal.

    Archive member names and everything read from a descriptor are untrusted,
    and a terminal acts on the control characters in what it is given: an
    escape sequence can clear the screen, retitle the window or rewrite what
    was printed before. So every C0 and C1 control character (U+0000 to
    U+001F and U+007F to U+009F), except a newline and a tab, is written as a
    visible escape instead, such as \\x1b for ESC. A format character
    (Unicode category Cf), which covers the bidirectional overrides and the
    zero-width characters that make text read differently from how it is
    stored, is written as \\uXXXX. So is a lone surrogate (category Cs),
    which is how a member name that is not valid UTF-8 is read, and which
    could not be printed at all. A backslash is written as two, so that text
    cannot pass for one of these escapes.
    """
    return ''.join(_printable_character(character) for character in str(text))


def _printable_character(character):
    if character == '\\':
        return '\\\\'
    if character in '\n\t':
        return character
    code = ord(character)
    if code < 0x20 or 0x7f <= code <= 0x9f:
        return '\\x%02x' % code
    if unicodedata.category(character) in ('Cf', 'Cs'):
        return '\\u%04x' % code if code <= 0xffff else '\\U%08x' % code
    return character


def _mib(size):
    mib = size / 1024 / 1024
    if mib == int(mib):
        return '%d' % mib
    return '%.2f' % mib


def _hardware_summary(hardware):
    """The lines describing one VirtualHardware, for the summary."""
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


def _archive_summary(package):
    """The lines describing an opened OVA: which member is which, and what the import leaves alone."""
    lines = [
        '    Descriptor: %s' % package.descriptor_member,
        '    Manifest: %s' % ('none' if package.manifest_member is None else package.manifest_member),
        '    Certificate: %s' % ('none' if package.certificate_member is None else package.certificate_member),
    ]
    unused = set(file.id for file in package.unused_files)
    for file in package.envelope.files:
        line = '    File %s: %s' % (file.id, package.file_members[file.id])
        if file.id in unused:
            line += ', which no disk uses, so it is neither verified nor uploaded'
        lines.append(line)
    for disk in package.blank_disks:
        lines.append('    Disk %s: no file, so it is created empty at deployment and not uploaded' % disk.disk_id)
    for member in package.unreferenced_members:
        lines.append('    Ignored, as nothing references it: %s' % member)
    return lines


def _archive_warnings(package):
    """The warnings and notices about an opened OVA's manifest and certificate, as lines."""
    lines = []
    if package.manifest_member is None:
        lines.append('Warning: the OVA has no manifest, so the disks cannot be checked for corruption.')
    elif package.manifest_name_differs:
        lines.append('Warning: the manifest %s is not named after the descriptor %s, as an OVA\'s manifest should be.'
                     % (package.manifest_member, package.descriptor_member))
    if package.unreferenced_entries:
        lines.append('Warning: the manifest has entries for members the descriptor does not reference, which are '
                     'not checked:')
        lines.extend('    %s' % entry.name for entry in package.unreferenced_entries)
    if package.certificate_member is not None:
        lines.append('Notice: the OVA has the certificate %s, whose signature was not checked.'
                     % package.certificate_member)
    return lines


def _refuse(message):
    """Print why the import stops, as untrusted text, and exit 1."""
    print(_printable(message))
    sys.exit(1)


def _artifact_names(package, system_id):
    """Each upload's artifact name, in order, refusing a name that Shaken Fist would refuse only after the upload."""
    names = []
    for upload in package.uploads:
        name = '%s-%s' % (system_id, upload.disk.disk_id)
        if '/' in name:
            print()
            _refuse('The artifact name "%s", made from the VirtualSystem\'s ovf:id and the Disk\'s ovf:diskId, '
                    'contains a /, which an artifact name may not' % name)
        names.append(name)
    return names


def _verify(package, blob_search):
    """Read each disk that needs reading once, checking it against the manifest, and return each upload's digests.

    With a manifest, every disk is read for its manifest algorithm. When the
    server can search for a blob by hash, every disk is read for SHA-512 as
    well, in the same read. Otherwise a disk is not read until it is uploaded.
    """
    if package.manifest is not None or blob_search:
        print()
        print('Checking disk images...')

    digests = []
    for upload in package.uploads:
        entry = package.manifest_entry(upload.member)
        algorithms = [] if entry is None else [entry.algorithm]
        if blob_search and 'sha512' not in algorithms:
            algorithms.append('sha512')
        if not algorithms:
            digests.append({})
            continue

        with tqdm(total=package.member_size(upload.member), unit='B', unit_scale=True,
                  desc=_printable('Reading %s' % upload.member)) as progress:
            computed = package.digests(upload.member, algorithms, progress.update)
        if entry is not None:
            package.check_digest(upload.member, computed)
            print(_printable('    %s: its %s digest matches the manifest' % (upload.member, entry.algorithm.upper())))
        digests.append(computed)
    return digests


def _one_line(value):
    """value with its whitespace collapsed to single spaces, or '' when it is not text."""
    if isinstance(value, bytes):
        value = value.decode('utf-8', 'replace')
    if not isinstance(value, str):
        return ''
    return ' '.join(value.split())


def _api_error(e):
    """What the server said when it refused a request, on one line.

    That is the error a JSON body gives, the body itself when it gives none,
    or the client's own message when the body is empty, absent or not text.
    """
    try:
        body = json.loads(e.text)
    except (TypeError, ValueError, RecursionError):
        body = None
    reason = ''
    if isinstance(body, dict):
        reason = _one_line(body.get('error'))
    if not reason:
        reason = _one_line(e.text)
    if not reason:
        reason = _one_line(e.message) or 'no reason given'
    return 'the server answered %s: %s' % (e.status_code, reason)


def _existing_artifacts(client, names):
    """For each artifact name, the existing artifact an upload under it goes into, or None for a new one.

    An artifact is identified by its name in the caller's namespace. A name is
    looked up across every artifact the caller can see, which includes shared
    artifacts and those of namespaces that trust the caller, but the caller's
    own namespace is searched first. So an artifact found anywhere else is not
    the one an upload goes into, and the upload makes a new artifact instead.

    The server finds the artifact an upload goes into by the source URL it
    gives uploads, made from the namespace and the name. An artifact of the
    caller's with the name but another source URL, such as one cached from a
    URL, would not be found, and the upload would make a second artifact of
    that name, which the name would then no longer look up. So that is refused.
    """
    existing = []
    for name in names:
        try:
            artifact = client.get_artifact(name)
        except apiclient.ResourceNotFoundException:
            artifact = None
        except apiclient.APIException as e:
            print()
            _refuse('Could not look up the artifact %s: %s' % (name, _api_error(e)))
        if artifact is not None and artifact['namespace'] != client.namespace:
            artifact = None
        if artifact is not None and artifact['source_url'] != 'sf://upload/%s/%s' % (client.namespace, name):
            print()
            _refuse('An artifact named %s already exists in the namespace %s, but was not created by an upload, '
                    'so the import cannot add to it: rename or delete the artifact %s first'
                    % (name, client.namespace, artifact['uuid']))
        existing.append(artifact)
    return existing


def _upload(client, package, path, names, existing, digests, blob_search):
    """Upload each disk, or reuse the blob already holding it, as one artifact per disk.

    The server gives each artifact its source URL. Where the disk came from is
    recorded in the artifact's metadata instead, as ova_file, the OVA's real
    path, and ova_member, the disk's member name.
    """
    print()
    print('Uploading disk images...')

    for upload, name, artifact, computed in zip(package.uploads, names, existing, digests):
        size = package.member_size(upload.member)
        print()
        if artifact is None:
            destination = 'a new artifact'
        else:
            destination = 'into the existing artifact %s' % artifact['uuid']
        print(_printable('%s with size %s, as the artifact %s, %s'
                         % (upload.member, humanize.naturalsize(size), name, destination)))

        blob = None
        if blob_search:
            print('Searching for a pre-existing blob with this hash...')
            blob = client.get_blob_by_sha512(computed['sha512'])

        if blob:
            print('Disk is already present in the cluster')
            artifact = client.blob_artifact(name, blob['uuid'])
        else:
            with package.open_member(upload.member) as f:
                artifact = util.upload_artifact_with_progress_file_like_object(client, name, f, size, None)
        print('Disk artifact is %s' % artifact['uuid'])

        try:
            client.set_artifact_metadata_item(artifact['uuid'], 'ova_file', path)
            client.set_artifact_metadata_item(artifact['uuid'], 'ova_member', upload.member)
        except apiclient.APIException as e:
            print()
            _refuse('The disk %s is in the artifact %s, but the artifact\'s metadata was not set: %s'
                    % (upload.member, artifact['uuid'], _api_error(e)))


def _import_package(client, package, path, accept_eula):
    """Describe an opened OVA, stop if it cannot be imported as it is, and then verify and upload its disks."""
    print('Archive members:')
    for line in _archive_summary(package):
        print(_printable(line))
    warnings = _archive_warnings(package)
    if warnings:
        print()
        for line in warnings:
            print(_printable(line))
    print()

    envelope = package.envelope
    version = envelope.version
    if version is None:
        version = 1
    name = envelope.virtual_system.id

    print('VM description:')
    for line in _envelope_summary(envelope, version, name):
        print(_printable(line))

    eulas = envelope.virtual_system.eulas
    for eula in eulas:
        print()
        print('Licence agreement:')
        print(_printable(eula.license))
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
            print(_printable(
                '    %s' % (prop.key if not prop.label else '%s (%s)' % (prop.key, prop.label))))

    names = _artifact_names(package, name)
    blob_search = client.check_capability('blob-search-by-hash')
    existing = _existing_artifacts(client, names)
    try:
        # Every disk is checked before any is uploaded, so that a corrupt
        # second disk does not leave the first behind as an artifact.
        digests = _verify(package, blob_search)
        _upload(client, package, path, names, existing, digests, blob_search)
    except ovf.OVFError as e:
        print()
        _refuse(e)


@ova.command(name='import', help='Import an OVA file')
@click.argument('source', type=click.Path(exists=True, dir_okay=False, readable=True))
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

    try:
        package = ovf.open_package(source)
    except ovf.OVFError as e:
        _refuse(e)
    with package:
        _import_package(ctx.obj['CLIENT'], package, os.path.realpath(source), accept_eula)


ova.add_command(ova_import)


def load(cli):
    cli.add_command(ova)
