"""The standard properties of the CIM classes a descriptor's hardware uses.

A hardware item's children in the rasd, sasd and epasd namespaces, and a
System's children in the vssd namespace, are the properties of a CIM class. For
each class, the parser either reads a property, or it is one of the class's
standard properties that the parser deliberately leaves unread. A name in one
of these namespaces that is in neither set, such as rasd:Unknown or oVirt's
rasd:cpu_per_socket, is not a property of the class, and is refused like any
other unread element.

The names were taken from the DMTF's XML schema for each class, fetched on
2026-10-17 from the URL given with each class (each file served with a
Last-Modified date of 2020-08-26). A class's properties are the elements its
<class>_Type complexType references. They are written out here, never fetched
at runtime.

SASD and EPASD are subclasses of RASD: each has every RASD property, plus its
own. The parser reads the same properties in all three.
"""

from . import namespaces


# CIM_ResourceAllocationSettingData, 29 properties.
# https://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData.xsd
RASD_READ = frozenset([
    'AddressOnParent', 'AllocationUnits', 'Connection', 'ElementName', 'HostResource', 'InstanceID', 'Parent',
    'ResourceSubType', 'ResourceType', 'VirtualQuantity', 'VirtualQuantityUnits',
])
# Unread: labels, the producer's own bookkeeping, and host-side allocation and scheduling hints Shaken Fist cannot
# honour.
RASD_UNUSED = frozenset([
    # Labels.
    'Caption', 'Description', 'OtherResourceType',
    # The producer's bookkeeping.
    'ChangeableType', 'ComponentSetting', 'ConfigurationName', 'Generation', 'SoID', 'SoOrgID',
    # Host-side allocation and scheduling hints.
    'AutomaticDeallocation', 'ConsumerVisibility', 'Limit', 'MappingBehavior', 'PoolID', 'Reservation', 'Weight',
    # A NIC's MAC address or a controller's bus number, and whether a device is connected at power-on. Both are
    # common, and Shaken Fist assigns its own addresses and attaches every device it creates.
    'Address', 'AutomaticAllocation',
])

# CIM_StorageAllocationSettingData, 38 properties.
# https://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_StorageAllocationSettingData.xsd
SASD_READ = RASD_READ
# Unread: RASD's unread properties, and where the host stores the extent, which Shaken Fist decides for itself.
SASD_UNUSED = RASD_UNUSED | frozenset([
    'HostExtentName', 'HostExtentNameFormat', 'HostExtentNameNamespace', 'HostExtentStartingAddress',
    'HostResourceBlockSize', 'OtherHostExtentNameFormat', 'OtherHostExtentNameNamespace',
])
# Standard properties that change what the guest sees (a read-only disk, the block size the guest is shown), which
# Shaken Fist cannot honour. They are neither read nor unused, so a descriptor carrying one is refused. None appears
# in the descriptor corpus.
SASD_REFUSED = frozenset(['Access', 'VirtualResourceBlockSize'])

# CIM_EthernetPortAllocationSettingData, 51 properties.
# https://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_EthernetPortAllocationSettingData.xsd
EPASD_READ = RASD_READ
# Unread: RASD's unread properties.
EPASD_UNUSED = RASD_UNUSED
# The switch port's VLAN, filtering, bandwidth and profile policy, which change what the guest's network does and
# which Shaken Fist cannot honour. They are neither read nor unused, so a descriptor carrying one is refused. None
# appears in a DMTF-namespaced item in the descriptor corpus.
EPASD_REFUSED = frozenset([
    'AllowedPriorities', 'AllowedToReceiveMACAddresses', 'AllowedToReceiveVLANs', 'AllowedToTransmitMACAddresses',
    'AllowedToTransmitVLANs', 'DefaultPortVID', 'DefaultPriority', 'DesiredVLANEndpointMode', 'GroupID',
    'ManagerID', 'NetworkPortProfileID', 'NetworkPortProfileIDType', 'OtherEndpointMode',
    'OtherNetworkPortProfileIDTypeInfo', 'PortCorrelationID', 'PortVID', 'Promiscuous', 'ReceiveBandwidthLimit',
    'ReceiveBandwidthReservation', 'SourceMACFilteringEnabled', 'VSITypeID', 'VSITypeIDVersion',
])

# CIM_VirtualSystemSettingData, 27 properties.
# https://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData.xsd
VSSD_READ = frozenset(['VirtualSystemIdentifier', 'VirtualSystemType'])
# Unread: labels, the producer's own bookkeeping, and the host's file locations and power-on and power-off
# behaviour, which Shaken Fist cannot honour.
VSSD_UNUSED = frozenset([
    # Labels.
    'Caption', 'Description', 'ElementName', 'Notes',
    # The producer's bookkeeping.
    'ChangeableType', 'ComponentSetting', 'ConfigurationID', 'ConfigurationName', 'CreationTime', 'Generation',
    'InstanceID', 'SoID', 'SoOrgID',
    # The host's file locations.
    'ConfigurationDataRoot', 'ConfigurationFile', 'LogDataRoot', 'RecoveryFile', 'SnapshotDataRoot',
    'SuspendDataRoot', 'SwapFileDataRoot',
    # The host's power-on and power-off behaviour.
    'AutomaticRecoveryAction', 'AutomaticShutdownAction', 'AutomaticStartupAction', 'AutomaticStartupActionDelay',
    'AutomaticStartupActionSequenceNumber',
])

# Every standard property of each class, keyed by the class's namespace.
PROPERTIES = {
    namespaces.RASD: RASD_READ | RASD_UNUSED,
    namespaces.SASD: SASD_READ | SASD_UNUSED | SASD_REFUSED,
    namespaces.EPASD: EPASD_READ | EPASD_UNUSED | EPASD_REFUSED,
    namespaces.VSSD: VSSD_READ | VSSD_UNUSED,
}

# The standard properties the parser leaves unread, keyed by the class's namespace.
UNUSED = {
    namespaces.RASD: RASD_UNUSED,
    namespaces.SASD: SASD_UNUSED,
    namespaces.EPASD: EPASD_UNUSED,
    namespaces.VSSD: VSSD_UNUSED,
}
