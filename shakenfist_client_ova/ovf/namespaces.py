"""The XML namespace URIs the parser knows, named once.

Every namespace URI the parser compares against is defined here. The producer
quirks in quirks.py and the CIM property lists in cim.py refer to these names
rather than repeating the URIs.
"""


# The OVF envelope. DSP0243 1.x and 2.x each have their own namespace, and the
# parser reads both the same way.
# https://www.dmtf.org/sites/default/files/standards/documents/DSP0243_1.1.0.pdf
OVF_1 = 'http://schemas.dmtf.org/ovf/envelope/1'
# https://www.dmtf.org/sites/default/files/standards/documents/DSP0243_2.1.1.pdf
OVF_2 = 'http://schemas.dmtf.org/ovf/envelope/2'
OVF_ENVELOPES = frozenset([OVF_1, OVF_2])

# VMware's pre-standard OVF 0.9 envelope. The parser does not read it, and
# names it when it refuses one.
OVF_0_9 = 'http://www.vmware.com/schema/ovf/1/envelope'

# The CIM classes a hardware item's and a System's properties belong to.
_CIM_SCHEMA = 'http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/'
RASD = _CIM_SCHEMA + 'CIM_ResourceAllocationSettingData'
VSSD = _CIM_SCHEMA + 'CIM_VirtualSystemSettingData'
SASD = _CIM_SCHEMA + 'CIM_StorageAllocationSettingData'
EPASD = _CIM_SCHEMA + 'CIM_EthernetPortAllocationSettingData'

# The same two CIM classes as VirtualBox's OVF 2.0 export names them, with the
# schema file's suffix. quirks.py reads them as SASD and EPASD.
VIRTUALBOX_SASD = SASD + '.xsd'
VIRTUALBOX_EPASD = EPASD + '.xsd'

# The W3C's XML Schema instance namespace, for xsi:schemaLocation and xsi:type.
XSI = 'http://www.w3.org/2001/XMLSchema-instance'

# The namespace the xml: prefix is bound to, for xml:lang.
XML = 'http://www.w3.org/XML/1998/namespace'

# VMware's extension namespace, which ovftool writes vmw:osType in.
VMWARE = 'http://www.vmware.com/schema/ovf'

# oVirt's extension namespace. A descriptor that declares it is an oVirt export.
OVIRT = 'http://www.ovirt.org/ovf'
