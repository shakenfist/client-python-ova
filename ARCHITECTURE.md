# Architecture

## Overview

`shakenfist_client_ova` is an `sf-client` plugin. `pyproject.toml`
registers its `load()` function in the `shakenfist_client.plugin`
entry point group, and `sf-client` calls it at startup to attach the
`ova` Click group. All of the code is in
`shakenfist_client_ova/__init__.py`.

The plugin talks to Shaken Fist only through `shakenfist_client`: an
`apiclient.Client` for the API, and the upload and checksum helpers in
`shakenfist_client.util`, which is where the 0.7.6 floor on that
dependency comes from.

## Import pipeline

`ova import` is one Click command that works through the archive in
four stages without extracting it to disk. Each archive member is
read through `tarfile.extractfile()` as a stream.

| Stage | Input | Output |
|-------|-------|--------|
| Classify | tar member names | lists of `.ovf`, `.vmdk`, `.mf` and other members |
| Manifest | `.mf` members | `(algorithm, hash)` per file name |
| Descriptor | `.ovf` members | the VM name, file references, disks, networks and a `hardware` dictionary |
| Upload | `.vmdk` members | one artifact per disk |

The hardware description is not yet turned into an instance, and the
manifest hashes are not yet checked; both are where the import is
expected to grow.

## Parsing by consumption

The descriptor is parsed with `xmltodict`, with the OVF, CIM and
vendor namespaces mapped to short prefixes (`v1`, `rasd`, `vssd`,
`vbox`, `vmware`) by the `NAMESPACES` table, so the code addresses
elements as `v1:Envelope`, `rasd:ResourceType` and so on.

Each section is read with `dpath` and then deleted from the parsed
dictionary. Sections known to carry nothing useful are deleted unread.
Once every known section is gone, an empty dictionary means the whole
descriptor was understood; anything left is printed and the import
stops. This makes support for a new appliance an explicit decision
about each section it carries, rather than a silent omission -- the
reasoning is in `docs/usage.md`.

Virtual hardware items are dispatched on their CIM
`ResourceAllocationSettingData` resource type. Storage controllers are
recorded by instance id so that disk drives, which name their
controller as a parent, can be placed on the right bus.

## Disk upload

Before uploading a disk, the plugin asks the server whether it
supports the `blob-search-by-hash` capability. If it does, the disk is
checksummed and an existing blob with the same content is wrapped in a
new artifact rather than uploaded again. Otherwise the disk is
streamed straight from the archive.

## Build and packaging

Packaging is `pyproject.toml` with setuptools, the version derived
from `v*` tags by setuptools_scm. `specifications/` holds the DMTF OVF
standards for reference and ships in neither the wheel nor the sdist.
Releases, CI and linting are described in `docs/development.md`.
