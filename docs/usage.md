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
3. **Parses the OVF descriptor.** The descriptor is read for the
   virtual machine's name, its file references, its disks and their
   capacities, its networks, and its virtual hardware: vCPU count,
   memory, IDE, SCSI and SATA (AHCI) controllers, network interfaces,
   and which disk sits on which controller. Floppy, CD and DVD drives,
   USB controllers, video and sound cards are recognised and ignored.
   Once it has parsed, the command prints a "VM description:"
   summary of what it found.
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

The OVF parser is deliberately strict. Each section it understands is
removed from the parsed descriptor as it is read, and a short list of
sections known to carry nothing useful (annotations, product and
operating system descriptions, VirtualBox and VMware extensions) is
removed unread. If anything is left at the end, the import stops and
prints what remains as JSON. The same happens for a hardware element
of a type the parser does not know, and for an allocation unit it
cannot convert to bytes. A descriptor the parser cannot read at all,
because it is not well-formed XML or not in a form it understands,
stops the import with a one-line error naming the problem.

That is the intended behaviour: an OVA whose description is only
partly understood would otherwise become an instance that is subtly
different from the appliance its author built. The JSON printed is
the starting point for teaching the parser about the new section.

## Standards

The DMTF OVF specifications the parser was written against are kept
in `specifications/` in the repository: DSP0243 versions 1.1.0 and
2.1.1, and DSP0265.
