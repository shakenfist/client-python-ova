# Importing an OVA

The plugin adds one command to `sf-client`:

```bash
sf-client ova import appliance.ova
```

An administrator can import into a namespace other than their own
with `--namespace <name>`.

## What an import does today

1. **Lists the archive.** An OVA is a tar file. Its members are sorted
   into the OVF descriptor (`.ovf`), disk images (`.vmdk`), manifests
   (`.mf`) and anything else, and the four lists are printed.
2. **Reads the manifest.** Each `SHA1(...) = ...` or
   `SHA256(...) = ...` line is parsed and the hash recorded against
   its file. A manifest line that does not parse stops the import.
   The hashes are not yet checked against the disk images.
3. **Parses the OVF descriptor.** The descriptor is read for:
   the envelope's OVF version; its files; its disks and their
   capacities (DSP0004 units, with `${property}` capacities
   resolved); its networks; its deployment options, where the
   default configuration is applied; the virtual system's id and
   name; the operating system; products and their properties;
   licences; and virtual hardware. Hardware means vCPUs, memory,
   IDE, SCSI, SATA and NVMe controllers, network interfaces, which
   disk sits on which controller, the system type and the transport.
   Floppy, CD and DVD drives, USB, video and sound are recognised
   and left to the instance's defaults. Once it has parsed, the
   command prints a "VM description:" summary of what it found. If
   the descriptor carries a licence, the command prints it and
   stops unless you pass `--accept-eula`. If it has user-configurable
   properties with no value, the command warns once that Shaken Fist
   cannot deliver an OVF environment yet.
4. **Uploads the disks.** Each `.vmdk` is uploaded to the cluster as a
   blob and wrapped in an artifact named after the virtual machine,
   with a source URL of `ova://<path to the OVA>/<disk name>`. Where
   the server supports searching blobs by hash, the disk is
   checksummed first and an existing blob reused rather than uploaded
   again.
5. **Prints the hardware description** it derived from the
   descriptor.

The import does not yet create an instance from what it has parsed.

## When an import stops

The OVF parser is deliberately strict. Anything it does not read is
either ignored or refused. It is ignored when it is:

* inside an element marked `ovf:required="false"`, including unread
  content within a section the parser does read, if that section is
  marked not required;
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
* A reference to a file, disk, controller or configuration that does
  not exist: `BrokenReferenceError`.
* Required content missing: `MissingContentError`.
* A value that does not parse: `InvalidValueError`.
* An allocation unit that is not a byte count:
  `UnknownAllocationUnitError`.
* A hardware resource type the parser does not know, unless the item
  is marked not required: `UnsupportedHardwareError`.
* A descriptor that is not well-formed XML, or that declares an
  entity: `MalformedDescriptorError` or `EntityDeclarationError`.

That is the intended behaviour: an OVA whose description is only
partly understood would otherwise become an instance that is subtly
different from the appliance its author built. Some producers write
descriptors that deviate from the schema; the parser accepts the known
ones (VirtualBox's `.xsd`-suffixed CIM namespaces, `InstanceId` for
`InstanceID`, VMware's unqualified attributes, and a drive's disk
reference written without its `ovf:` prefix). The plan for what
remains is in [the OVF parser plan](plans/PLAN-ovf-parser.md).

## Standards

The DMTF OVF specifications the parser was written against are kept
in `specifications/` in the repository: DSP0243 versions 1.1.0 and
2.1.1, and DSP0265.
