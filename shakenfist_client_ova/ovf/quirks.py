"""The producer quirks the parser accepts, and the producer it refuses by name.

Real producers write a few things the OVF and CIM schemas do not allow. Each
deviation accepted here names its producer and the evidence for it: a fixture
under tests/fixtures/ovf/, or descriptors in the upstream corpus the descriptor
corpus tier fetches. A deviation that is not here is refused like any other
unread content. When a new producer quirk turns up, it is added here, with its
evidence, rather than special-cased in the parser.

The unqualified-attribute rule
------------------------------

An unqualified attribute on an element in an OVF envelope namespace is read as
the OVF attribute of the same name, wherever the parser reads that attribute.
VMware's ovftool writes Item@configuration, Value@configuration, Value@value
and License@msgid unqualified: Item@configuration in VyOS 1.2.1
(tests/fixtures/ovf/vendor/vyos-1.2.1.ovf) and hundreds of Items in the corpus,
and License@msgid in both Photon OS fixtures. An element carrying both the
qualified and the unqualified form of one attribute is refused, because the two
could disagree. An unqualified attribute the parser does not read is refused
like a qualified one.
"""

from . import namespaces


# CIM namespaces written under another URI, mapped to the namespace they mean.
# The parser reads an element or attribute in a key's namespace exactly as if
# it were in the value's.
NAMESPACE_ALIASES = {
    # VirtualBox's OVF 2.0 export suffixes these two class namespaces with
    # ".xsd", naming the schema file rather than the namespace. Evidence:
    # ArchiveTeam Warrior 4.1 (tests/fixtures/ovf/vendor/archiveteam-warrior-4.1.ovf)
    # and COT's tests/ubuntu.2.0.ovf in the corpus.
    namespaces.VIRTUALBOX_EPASD: namespaces.EPASD,
    namespaces.VIRTUALBOX_SASD: namespaces.SASD,
}

# The namespaces in which InstanceId is read as the InstanceID property. VMware
# (ovftool's test templates in the govmomi corpus) and VirtualBox (its OVF 0.9
# export, as in tests/fixtures/ovf/vendor/tails-202607.ovf) write InstanceId,
# in both the rasd and vssd namespaces, hundreds of times across the corpus.
# Applied after NAMESPACE_ALIASES, so VirtualBox's suffixed namespaces are
# covered by their DMTF names.
INSTANCE_ID_NAMESPACES = frozenset([namespaces.RASD, namespaces.VSSD, namespaces.SASD, namespaces.EPASD])

# Element names read as another, keyed by (namespace, local name).
ELEMENT_ALIASES = {(namespace, 'InstanceId'): 'InstanceID' for namespace in INSTANCE_ID_NAMESPACES}

# The prefixes with which a HostResource may name a disk or a file in the
# descriptor: the specification's "ovf:" form (ovf:/disk/<diskId>), and the bare
# form (/disk/<diskId>). VirtualBox writes the bare form, in ArchiveTeam Warrior
# 4.1 (tests/fixtures/ovf/vendor/archiveteam-warrior-4.1.ovf), both CyberOps
# fixtures (tests/fixtures/ovf/vendor/cyberops-*.ovf) and vulnhub-blogger.ovf.
# 189 descriptors in the upstream corpus write it too, 186 for a disk and 3 for
# a file: one in COT's corpus and the rest in govmomi's, mostly VMware ovftool
# templates and test files. Both forms are checked alike, and the text is kept
# as written.
HOST_RESOURCE_PREFIXES = ('ovf:', '')

# oVirt writes its own dialect of OVF, not a few extra attributes: Oracle Linux
# 9.8's OLVM template (tests/fixtures/ovf/vendor/oracle-linux-9.8-olvm.ovf)
# carries 33 oVirt elements under VirtualSystem, the template's cloud-init
# configuration in VmInit, unqualified and non-CIM children of Item, and a
# resource type CIM does not define. A descriptor that declares this namespace
# anywhere is refused as an oVirt export rather than read in part.
OVIRT_NAMESPACE = namespaces.OVIRT

# Property types outside the specification's table, accepted as well as its
# own. They are written here in lower case and matched in any case. They are
# vSphere's vApp property types, which VMware's tooling writes as a Property's
# ovf:type: int for an integer and real for a floating-point number. govmomi's
# corpus fixtures carry int in qualifiers.ovf, property-types.ovf,
# deployment-configs.ovf, disk-capacity-property.ovf, uber.ovf and
# multiple_disks.ovf, and real in qualifiers.ovf; govmomi's ovf/configspec.go
# maps int to vSphere's type with the comment "common in OVF although not in
# DSP0243 Table 6".
PROPERTY_TYPES = frozenset(['int', 'real'])

# The attribute in which a producer marks a disk as the boot disk. The
# specification does not define it, but the parser reads it into Disk.boot
# rather than refusing it; every other undefined attribute in an OVF namespace
# is still refused. The Home Assistant OS OVA build writes it on its one disk
# (tests/fixtures/ovf/vendor/home-assistant-os-18.3.ovf), capitalised as
# "True". oVirt writes it on its disks too (the Oracle Linux 9.8 OLVM template,
# tests/fixtures/ovf/vendor/oracle-linux-9.8-olvm.ovf), though that export is
# refused as an oVirt export all the same. No descriptor in the upstream corpus
# carries it. Its value is read as true or false in any case, because of the
# capital.
DISK_BOOT_ATTRIBUTE = 'ovf:boot'
