# Importing an OVA

The plugin adds one command to `sf-client`:

```bash
sf-client ova import appliance.ova
```

An administrator can import into a namespace other than their own
with `--namespace <name>`.

## What an import does today

1. **Opens the archive and prints its summary.** An OVA must be a
   plain, uncompressed tar file. The command finds the descriptor
   (the one top-level `.ovf` member), the manifest (`.mf`) and the
   certificate (`.cert`), matching those suffixes in lower case as
   DSP0243 gives them, so `APPLIANCE.OVF` is not found, checks the archive against them, and prints
   "Archive members:": which member is the descriptor, the manifest
   and the certificate, which member holds each file the descriptor
   lists, each disk that has no file (it is created empty at
   deployment and not uploaded), and each member nothing references,
   which is ignored. A file that no disk uses, such as an ISO, is
   marked as neither verified nor uploaded. After the summary come
   any warnings: there is no manifest, the manifest is not named after
   the descriptor, the manifest lists members the descriptor does not
   reference (they are not checked), and the notice that a
   certificate's signature was not checked.
2. **Reads the manifest first.** If there is a manifest it is read
   wherever it sits in the archive. Each `SHA1(...) = ...`,
   `SHA256(...) = ...` or `SHA512(...) = ...` line is parsed. The
   import stops on a line that does not parse, an algorithm other than
   those three, a digest that is not hexadecimal of its algorithm's
   length, a second line for one file, or a manifest that is not
   UTF-8. CRLF line endings are accepted, and digests are compared
   without regard to case.
3. **Verifies the descriptor, then parses it.** The descriptor's
   digest is checked against the manifest before the descriptor is
   parsed, so a descriptor that does not match is refused without
   being interpreted. The descriptor is read for: the envelope's OVF
   version; its files; its disks and their capacities (DSP0004 units,
   with `${property}` capacities resolved) and the disk the producer
   marks as the boot disk; its networks; its deployment options, where
   the default configuration is applied; the virtual system's id and
   name; the operating system; products and their properties;
   licences; and virtual hardware. Hardware means vCPUs, memory, IDE,
   SCSI, SATA and NVMe controllers, network interfaces, which disk
   sits on which controller, the system type and the transport.
   Floppy, CD and DVD drives, USB, video and sound are recognised and
   left to the instance's defaults.
4. **Checks the files against the descriptor.** The disks to upload
   come from the descriptor's `DiskSection` and the files its
   `References` name, not from member suffixes. Each file's member
   must exist and be a regular file of the size the descriptor gives,
   uncompressed, not chunked, and listed in the manifest if there is
   one; no disk may be a delta disk.
5. **Prints "VM description:"** once, before any disk is read, with
   what the descriptor says. A descriptor without `ovf:version` is
   shown as "not stated", with the major version its envelope
   namespace implies, such as `1.x`. If the descriptor carries a
   licence, the command prints it and stops unless you pass
   `--accept-eula`. If it has user-configurable properties with no
   value, the command warns once that Shaken Fist cannot deliver an OVF
   environment yet.
6. **Verifies the disks in one pass.** With a manifest, every disk is
   read once and its digest, in the manifest's algorithm, compared
   with the manifest's, and "Checking disk images..." is printed
   first. Where the server supports searching blobs by hash, the same
   read also computes the disk's SHA-512, so a blob already in the
   cluster can be reused. With neither a manifest nor blob search, a
   disk is not read until it is uploaded. Every disk is checked before
   any is uploaded, so that a corrupt second disk does not leave the
   first behind as an artifact. The upload in the next step reads each
   disk again, and that read is not checked.
7. **Uploads the disks.** Each disk is uploaded as a blob, or an
   existing blob with the same SHA-512 is reused, and wrapped in an
   artifact named `<system>-<disk>`, from the virtual system's
   `ovf:id` and the disk's `ovf:diskId`. No source URL is sent, so the
   server gives each artifact `sf://upload/<namespace>/<artifact name>`.
   An artifact is identified by its name in your namespace. Before any
   disk is read, the import looks each name up and says, for each disk,
   whether it goes to a new artifact or "into the existing artifact
   <uuid>". Importing an unchanged disk again adds no
   version, because the server skips a version whose content matches
   the latest. An artifact of yours with that name that was not made
   by an upload, for example one cached from a URL, is refused: rename
   or delete it first. Each artifact gets two metadata keys, `ova_file`,
   the OVA's real path with any symlinks resolved, and `ova_member`,
   the disk's member name. A name containing a `/` is refused before
   anything is read, because Shaken Fist would refuse it only after
   the upload.

The import does not yet create an instance from what it has parsed.

Everything it prints that comes from the OVA, such as member names,
the summary, a licence, or an error quoting the descriptor, has its
control characters written as visible escapes, such as `\x1b` for
ESC, so that an OVA cannot send escape sequences to your terminal. So
do format characters such as bidirectional overrides, and the lone
surrogates by which a member name that is not valid UTF-8 is read.

## What the manifest does and does not do

The manifest detects corruption and accidental mismatch: a download
cut short, a disk damaged in storage, a descriptor from one export
paired with disks from another. It does not detect tampering. Anyone
who can change the descriptor or a disk can rewrite or remove the
manifest to match, and nothing in the OVA says who wrote it.

The upload reads each disk from the archive again, and that second
read is not checked against the manifest. An OVA changed on disk
during the import, to a file of the same size, would not be
detected.

The `.cert` member, if there is one, is not checked: its signature is
not verified and its certificate is not validated. The command says so
in a notice.

Without a manifest, nothing is verified, and the command warns that
the disks cannot be checked for corruption. Do not treat a passing
check as a statement that the appliance is safe to run.

## When an import stops

The OVF parser is deliberately strict. Anything it does not read is
either ignored or refused. It is ignored when it is:

* inside an element marked `ovf:required="false"`, including unread
  content within a section the parser does read, if that section is
  marked not required. Inside such a section, a hardware item's CIM
  properties are still checked as they are elsewhere, unless the item
  itself is marked not required;
* `Info`, `AnnotationSection` or `Strings`, or an `ovf:msgid`
  attribute;
* `xml:lang` or `xsi:schemaLocation`;
* an attribute in a namespace that is neither OVF's nor CIM's;
* one of a CIM class's standard properties the parser deliberately
  does not use (`ovf/cim.py`).

Anything else is refused with `UnparsedContentError`. Its message is
a heading and then one unread path per line, which is the starting
point for teaching the parser about the new content. A few standard
CIM properties that change what the guest sees, such as a read-only
disk or VLAN policy, are refused even though they are standard.

Other refusals are named, and each prints one line and exits 1:

* OVF 0.9 and other non-OVF envelopes: `UnsupportedEnvelopeError`.
* A `VirtualSystemCollection`, which holds several virtual
  machines: `VirtualSystemCollectionError`.
* oVirt exports, such as Oracle Linux's OLVM templates:
  `UnsupportedProducerError`. A reader is future work.
* A reference to a file, disk, controller, network or configuration
  that does not exist: `BrokenReferenceError`.
* Required content missing: `MissingContentError`.
* A value that does not parse, or an id or key repeated where it must
  be unique: `InvalidValueError`.
* An allocation unit that is not a byte count:
  `UnknownAllocationUnitError`.
* A hardware resource type the parser does not know, unless the item
  is marked not required: `UnsupportedHardwareError`.
* A descriptor that is not well-formed XML, or that declares an
  entity: `MalformedDescriptorError` or `EntityDeclarationError`.

The archive itself is checked before and around the descriptor, and
the first rule broken is the one reported. A plain tar is required: an
OVA that has been gzipped or otherwise compressed is refused, and so
is one that ends early. Each of these also prints one line and exits
1:

* A file that is not an uncompressed tar, or that ends early:
  `NotAnArchiveError`.
* Members that do not make a package: no descriptor or several, more
  than one manifest or certificate, a certificate without a manifest,
  two members with one name, a package member that is not a regular
  file, or a descriptor or manifest too large to read:
  `PackageLayoutError`.
* A file whose `ovf:href` cannot name a member: it is empty, has a URL
  scheme, starts with `/`, has a `.` or `..` segment, repeats another
  file's, or names the descriptor, manifest or certificate:
  `FileReferenceError`.
* A file split into chunks (`ovf:chunkSize`), which the importer does
  not join: `ChunkedFileError`.
* Files whose members the archive does not hold, all reported
  together: `MissingMemberError`.
* A file whose member is a link, directory or other non-regular
  member: `MemberTypeError`.
* A file whose `ovf:size` differs from its member's size:
  `FileSizeError`.
* A file with an `ovf:compression` other than none or `identity`:
  `CompressedFileError`.
* A manifest with no entry for the descriptor or for a file's member:
  `UnlistedFileError`.
* A manifest that cannot be read: a line that does not parse, an
  algorithm other than SHA1, SHA256 or SHA512, a digest of the wrong
  length or not hexadecimal, a second line for one file, or a manifest
  that is not UTF-8: `ManifestError`. Apart from an encoding failure,
  the message gives the line number.
* A descriptor or disk whose digest differs from the manifest's:
  `DigestMismatchError`.
* A delta disk (`ovf:parentRef`), which holds only the changes from
  its parent and alone would not boot: `DeltaDiskError`.

Three more refusals come from the server rather than the OVA. Each
prints one line and exits 1:

* A lookup of an artifact name that failed, before any disk is read.
* An artifact of yours with the name that was not made by an upload,
  which the import cannot add to. Rename or delete it.
* A metadata update that failed after the disk had landed. The line
  names the artifact the disk is in, so the metadata can be set by
  hand. The import stops there, so the OVA's later disks are not
  uploaded. Once the cause is fixed, run the import again: the disks
  already uploaded go "into the existing artifact", which sets their
  metadata, and the rest are uploaded as before.

That is the intended behaviour: an OVA whose description is only
partly understood would otherwise become an instance that is subtly
different from the appliance its author built. Some producers write
descriptors that deviate from the schema; the parser accepts the known
ones (VirtualBox's `.xsd`-suffixed CIM namespaces, `InstanceId` for
`InstanceID`, VMware's unqualified attributes and its `int` and
`real` property types, a drive's disk reference written without its
`ovf:` prefix, and the non-standard `ovf:boot` on a disk, read from
Home Assistant OS's build). The plan
for what remains is in [the OVF parser
plan](plans/PLAN-ovf-parser.md).

## Standards

The DMTF OVF specifications the parser was written against are kept
in `specifications/` in the repository: DSP0243 versions 1.1.0 and
2.1.1, and DSP0265.
