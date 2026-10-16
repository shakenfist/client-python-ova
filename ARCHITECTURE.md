# Architecture

## Overview

`shakenfist_client_ova` is an `sf-client` plugin. `pyproject.toml`
registers its `load()` function in the `shakenfist_client.plugin`
entry point group, and `sf-client` calls it at startup to attach the
`ova` Click group. The command is in
`shakenfist_client_ova/__init__.py`; the OVF descriptor and manifest
parser is the subpackage `shakenfist_client_ova/ovf/`, described
below.

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
| Manifest | `.mf` members, through `ovf.parse_manifest()` | a `Manifest` of `(name, algorithm, digest)` entries, from which the command records a hash per file name |
| Descriptor | `.ovf` members, through `ovf.parse_descriptor()` | an `Envelope`: the VM name, file references, disks, networks, deployment options, products and virtual hardware |
| Upload | `.vmdk` members | one artifact per disk |

The hardware description is not yet turned into an instance, and the
manifest hashes are not yet checked; both are where the import is
expected to grow.

## The OVF subpackage

`shakenfist_client_ova/ovf/` holds everything that reads an OVF
descriptor or a manifest: `descriptor.py` and `manifest.py` are the
parsers, `model.py` the dataclasses they return, `errors.py` the
errors they raise, and `prose.py` the list of prose elements shared
with `tools/trim-ovf-descriptor.py`. It is built to be spun out of
this repository, so it imports only the standard library and its
parsing dependencies, never `click` or `shakenfist_client`. It never
prints and never exits. `shakenfist_client_ova/tests/test_ovf_boundary.py`
reads the source of every module in it and fails on a forbidden
import, a `print` or an exit. That boundary covers the code inside
`ovf/` only: importing `shakenfist_client_ova.ovf` still runs the parent
package's `__init__.py`, which imports `click` and `shakenfist_client`,
so the subpackage cannot yet be used without the plugin's dependencies.

Every failure is an `OVFError` subclass, and the command prints its
message and exits 1: one line, or for `UnparsedContentError` a heading
and one unread path per line. `errors.py` lists them, and
`docs/usage.md` says what each one means for a person. The parser
returns an `Envelope` (a tree of plain dataclasses, serialised by
`ovf.to_json()`), with sizes in bytes. The command does all the
talking: it catches `OVFError`, prints its message and exits, and
prints the summary of the model.

## Reading with ElementTree

`ovf/descriptor.py` parses the descriptor with `defusedxml` and
ElementTree, addressing every element by its full namespace, so a
producer's choice of prefix does not matter. `namespaces.py` holds
the namespaces and `units.py` converts DSP0004 allocation units to
bytes. Virtual hardware items are dispatched on their CIM
`ResourceAllocationSettingData` resource type, and storage
controllers are recorded by instance id so that disk drives, which
name their controller as a parent, land on the right bus.

The parser marks each element and attribute it reads. When it has
finished, it walks the tree, and anything unmarked is either ignored
for a stated reason or refused with `UnparsedContentError`. This
makes support for a new appliance an explicit decision about each
piece of it, rather than a silent omission. The rule is in
`docs/usage.md`.

Two tables keep producer and standard knowledge out of the parser's
logic. `ovf/cim.py` lists, for each CIM class, the standard
properties the parser uses, the ones it deliberately leaves unused
and the few it refuses because they change what the guest sees.
`ovf/quirks.py` lists the producer deviations from the schema that
the parser accepts (VirtualBox's `.xsd`-suffixed CIM namespaces, the
`InstanceId` spelling, VMware's unqualified attributes), each with
its evidence. What is not yet read is tracked as Future work in
[the OVF parser plan](docs/plans/PLAN-ovf-parser.md).

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
