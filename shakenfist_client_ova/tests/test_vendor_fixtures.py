"""Each vendor fixture that parses, checked against values read off its descriptor by hand.

The golden tests compare every fixture with its expected file, which the parser
wrote. These tests are the second record of what a correct parse is: each value
below was worked out from the .ovf file itself, with allocation units converted
by hand, so a parser change that alters a vendor appliance's meaning fails here
even when its expected file is regenerated to match.

Vendor prose was replaced with TRIMMED when each fixture was cut down, so text
fields are asserted only where they were left as the vendor wrote them.
"""

import os

import testtools

from shakenfist_client_ova import ovf


VENDOR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures', 'ovf', 'vendor')

OVF_1 = 'http://schemas.dmtf.org/ovf/envelope/1'
OVF_2 = 'http://schemas.dmtf.org/ovf/envelope/2'
STREAM_OPTIMIZED = 'http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized'


def parse(name):
    with open(os.path.join(VENDOR, name + '.ovf'), 'rb') as f:
        return ovf.parse_descriptor(f.read())


class VendorFixtureTestCase(testtools.TestCase):
    def only_hardware(self, envelope):
        self.assertEqual(1, len(envelope.virtual_system.hardware))
        return envelope.virtual_system.hardware[0]

    def test_archiveteam_warrior_4_1(self):
        # VirtualBox's OVF 2.0 export: StorageItem and EthernetPortItem, in
        # namespaces suffixed with .xsd.
        envelope = parse('archiveteam-warrior-4.1')
        self.assertEqual(OVF_2, envelope.namespace)
        self.assertEqual('2.0', envelope.version)
        self.assertEqual(
            [ovf.File(id='file1', href='archiveteam-warrior-v4.1-20240906-215354-disk001.vmdk')], envelope.files)
        # No capacityAllocationUnits, so the capacity is in bytes.
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', capacity_bytes=64424509440, file_ref='file1', format=STREAM_OPTIMIZED)],
            envelope.disks)
        self.assertEqual(
            [ovf.Network(name='NAT', description='Logical network used by this appliance.')], envelope.networks)
        self.assertEqual([], envelope.deployment_options)

        system = envelope.virtual_system
        self.assertEqual('archiveteam-warrior-4.1', system.id)
        self.assertIsNone(system.name)
        # vbox:OSType is a VirtualBox element marked not required, not an osType attribute.
        self.assertEqual(ovf.OperatingSystem(id=102, description='Other_64'), system.operating_system)
        self.assertEqual(1, len(system.products))
        self.assertEqual('4.1', system.products[0].version)
        self.assertEqual([], system.products[0].properties)
        self.assertEqual([], system.eulas)

        hardware = self.only_hardware(envelope)
        self.assertEqual(1, hardware.vcpus)
        self.assertEqual(536870912, hardware.memory_bytes)     # 512 MegaBytes, 512 x 2^20
        self.assertEqual([ovf.Controller(instance_id='3', bus='sata')], hardware.controllers)
        # The drive's StorageItem has a Caption and no ElementName. VirtualBox
        # writes the HostResource without the ovf: scheme.
        self.assertEqual(
            [ovf.DiskDrive(parent='3', address_on_parent=0, host_resource='/disk/vmdisk1')], hardware.disk_drives)
        self.assertEqual([ovf.Nic(resource_subtype='E1000', connection='NAT')], hardware.nics)
        self.assertEqual('virtualbox-2.2', hardware.system_type)
        self.assertEqual('archiveteam-warrior-4.1', hardware.system_identifier)
        self.assertEqual([], hardware.transport)

    def test_cyberops_security_onion(self):
        envelope = parse('cyberops-security-onion')
        self.assertEqual(OVF_1, envelope.namespace)
        self.assertEqual('1.0', envelope.version)
        self.assertEqual([ovf.File(id='file1', href='CyberOps Security Onion-disk001.vmdk')], envelope.files)
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', capacity_bytes=21474836480, file_ref='file1', format=STREAM_OPTIMIZED)],
            envelope.disks)
        self.assertEqual(['Internal', 'NAT'], [network.name for network in envelope.networks])
        self.assertEqual([], envelope.deployment_options)

        system = envelope.virtual_system
        self.assertEqual('CyberOps Security Onion', system.id)
        self.assertEqual(ovf.OperatingSystem(id=94, description='Ubuntu_64'), system.operating_system)
        self.assertEqual(1, len(system.products))
        self.assertEqual([], system.products[0].properties)
        self.assertEqual([], system.eulas)

        hardware = self.only_hardware(envelope)
        self.assertEqual(1, hardware.vcpus)
        self.assertEqual(4294967296, hardware.memory_bytes)    # 4096 MegaBytes, 4096 x 2^20
        self.assertEqual(
            [ovf.Controller(instance_id='3', bus='ide'),
             ovf.Controller(instance_id='4', bus='ide'),
             ovf.Controller(instance_id='5', bus='sata')],
            hardware.controllers)
        # The sound card, resource type 35, is left to the instance's defaults.
        self.assertEqual(
            [ovf.DiskDrive(parent='5', address_on_parent=0, element_name='disk1', host_resource='/disk/vmdisk1')],
            hardware.disk_drives)
        self.assertEqual(
            [ovf.Nic(resource_subtype='E1000', connection='Internal'),
             ovf.Nic(resource_subtype='E1000', connection='Internal'),
             ovf.Nic(resource_subtype='E1000', connection='NAT')],
            hardware.nics)
        self.assertEqual('virtualbox-2.2', hardware.system_type)
        self.assertEqual('CyberOps Security Onion', hardware.system_identifier)

    def test_cyberops_workstation(self):
        envelope = parse('cyberops-workstation')
        self.assertEqual(OVF_1, envelope.namespace)
        self.assertEqual('1.0', envelope.version)
        self.assertEqual(
            [ovf.File(id='file1', href='CyberOps Workstation-disk001.vmdk'),
             ovf.File(id='file2', href='CyberOps Workstation-disk002.vmdk')],
            envelope.files)
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', capacity_bytes=10737418240, file_ref='file1', format=STREAM_OPTIMIZED),
             ovf.Disk(disk_id='vmdisk2', capacity_bytes=1073741824, file_ref='file2', format=STREAM_OPTIMIZED)],
            envelope.disks)
        self.assertEqual(['NAT'], [network.name for network in envelope.networks])
        self.assertEqual([], envelope.deployment_options)

        system = envelope.virtual_system
        self.assertEqual('CyberOps Workstation', system.id)
        self.assertEqual(ovf.OperatingSystem(id=100, description='Linux26_64'), system.operating_system)
        self.assertEqual(1, len(system.products))
        self.assertEqual([], system.products[0].properties)
        self.assertEqual([], system.eulas)

        hardware = self.only_hardware(envelope)
        self.assertEqual(1, hardware.vcpus)
        self.assertEqual(1073741824, hardware.memory_bytes)    # 1024 MegaBytes, 1024 x 2^20
        self.assertEqual(
            [ovf.Controller(instance_id='3', bus='ide'),
             ovf.Controller(instance_id='4', bus='ide'),
             ovf.Controller(instance_id='5', bus='sata')],
            hardware.controllers)
        self.assertEqual(
            [ovf.DiskDrive(parent='5', address_on_parent=0, element_name='disk1', host_resource='/disk/vmdisk1'),
             ovf.DiskDrive(parent='5', address_on_parent=1, element_name='disk2', host_resource='/disk/vmdisk2')],
            hardware.disk_drives)
        self.assertEqual([ovf.Nic(resource_subtype='E1000', connection='NAT')], hardware.nics)
        self.assertEqual('virtualbox-2.2', hardware.system_type)
        self.assertEqual('CyberOps Workstation', hardware.system_identifier)

    def test_fedora_coreos_44_20260928_3_1(self):
        envelope = parse('fedora-coreos-44.20260928.3.1')
        self.assertEqual(OVF_1, envelope.namespace)
        self.assertIsNone(envelope.version)
        self.assertEqual([ovf.File(id='file1', href='disk.vmdk', size=1101960704)], envelope.files)
        # capacityAllocationUnits="byte", which once failed to parse.
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', capacity_bytes=10737418240, file_ref='file1', format=STREAM_OPTIMIZED,
                      populated_size=1101960704)],
            envelope.disks)
        self.assertEqual(
            [ovf.Network(name='VM Network', description='The VM Network network')], envelope.networks)
        self.assertEqual([], envelope.deployment_options)

        system = envelope.virtual_system
        self.assertEqual('image', system.id)
        self.assertEqual('Fedora CoreOS stable', system.name)
        self.assertEqual(ovf.OperatingSystem(id=100, os_type='fedora64Guest'), system.operating_system)
        self.assertEqual(1, len(system.products))
        product = system.products[0]
        self.assertEqual('44.20260928.3.1', product.version)
        self.assertEqual(
            ['guestinfo.ignition.config.data', 'guestinfo.ignition.config.data.encoding'],
            [prop.key for prop in product.properties])
        for prop in product.properties:
            self.assertEqual('string', prop.type)
            self.assertTrue(prop.user_configurable)
            self.assertFalse(prop.password)
            self.assertEqual('', prop.value)
        self.assertEqual([], system.eulas)

        hardware = self.only_hardware(envelope)
        self.assertEqual(2, hardware.vcpus)
        self.assertEqual(4294967296, hardware.memory_bytes)    # 4096 x 2^20
        self.assertEqual([ovf.Controller(instance_id='3', bus='scsi')], hardware.controllers)
        # The VMCI device, resource type 1, is marked not required and passed over.
        self.assertEqual(
            [ovf.DiskDrive(parent='3', address_on_parent=0, element_name='Hard disk 0',
                           host_resource='ovf:/disk/vmdisk1')],
            hardware.disk_drives)
        self.assertEqual([ovf.Nic(resource_subtype='VmxNet3', connection='VM Network')], hardware.nics)
        self.assertEqual('vmx-17', hardware.system_type)
        self.assertEqual('image', hardware.system_identifier)
        self.assertEqual(['com.vmware.guestInfo'], hardware.transport)

    def test_flatcar_4757_2_1(self):
        envelope = parse('flatcar-4757.2.1')
        self.assertEqual(OVF_1, envelope.namespace)
        self.assertEqual(
            [ovf.File(id='file1', href='flatcar_production_vmware_ova_image.vmdk', size=590454272)], envelope.files)
        # capacityAllocationUnits="byte", which once failed to parse.
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', capacity_bytes=13212057600, file_ref='file1', format=STREAM_OPTIMIZED,
                      populated_size=0)],
            envelope.disks)
        self.assertEqual(['VM Network'], [network.name for network in envelope.networks])
        self.assertEqual([], envelope.deployment_options)

        system = envelope.virtual_system
        self.assertEqual('flatcar_production_vmware_ova', system.id)
        self.assertEqual('flatcar_production_vmware_ova', system.name)
        self.assertEqual(ovf.OperatingSystem(id=100, os_type='other3xLinux64Guest'), system.operating_system)

        # One ProductSection, marked not required, with no Product or Version
        # and 23 properties for VMware's guestinfo transport.
        self.assertEqual(1, len(system.products))
        product = system.products[0]
        self.assertIsNone(product.product)
        self.assertIsNone(product.version)
        self.assertEqual(23, len(product.properties))
        self.assertEqual('guestinfo.hostname', product.properties[0].key)
        self.assertEqual('guestinfo.interface.1.route.0.destination', product.properties[-1].key)
        values = {prop.key: prop.value for prop in product.properties}
        self.assertEqual('no', values['guestinfo.interface.0.dhcp'])
        self.assertEqual('public', values['guestinfo.interface.0.role'])
        self.assertEqual('no', values['guestinfo.interface.1.dhcp'])
        self.assertEqual('private', values['guestinfo.interface.1.role'])
        self.assertEqual('', values['guestinfo.ignition.config.data'])
        self.assertTrue(all(prop.user_configurable for prop in product.properties))
        self.assertFalse(any(prop.password for prop in product.properties))
        self.assertEqual([], system.eulas)

        hardware = self.only_hardware(envelope)
        self.assertEqual(2, hardware.vcpus)
        self.assertEqual(1073741824, hardware.memory_bytes)    # 1024 x 2^20
        self.assertEqual(
            [ovf.Controller(instance_id='3', bus='scsi'),
             ovf.Controller(instance_id='4', bus='ide'),
             ovf.Controller(instance_id='5', bus='ide')],
            hardware.controllers)
        # The CD-ROM on controller 4, the floppy, the video card and the VMCI
        # device are each marked not required, and none is a disk drive.
        self.assertEqual(
            [ovf.DiskDrive(parent='3', address_on_parent=0, element_name='Hard Disk 1',
                           host_resource='ovf:/disk/vmdisk1')],
            hardware.disk_drives)
        self.assertEqual([ovf.Nic(resource_subtype='VmxNet3', connection='VM Network')], hardware.nics)
        self.assertEqual('vmx-13', hardware.system_type)
        self.assertEqual(['com.vmware.guestInfo'], hardware.transport)

    def test_home_assistant_os_18_3(self):
        # Home Assistant OS's OVA build: a VMware-style descriptor from VirtualBox's export, with the
        # non-standard ovf:boot on its disk, written "True".
        envelope = parse('home-assistant-os-18.3')
        self.assertEqual(OVF_1, envelope.namespace)
        self.assertEqual('1.0', envelope.version)
        self.assertEqual([ovf.File(id='file1', href='home-assistant.vmdk')], envelope.files)
        # No capacityAllocationUnits, so the capacity is in bytes: 32 GiB.
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', capacity_bytes=34359738368, file_ref='file1', format=STREAM_OPTIMIZED,
                      boot=True)],
            envelope.disks)
        self.assertEqual(
            [ovf.Network(name='Bridged', description='Logical network used by this appliance.')], envelope.networks)
        self.assertEqual([], envelope.deployment_options)

        system = envelope.virtual_system
        self.assertEqual('HomeAssistant', system.id)
        self.assertEqual('Home Assistant', system.name)
        # vmw:osType is the only osType given.
        self.assertEqual(
            ovf.OperatingSystem(id=102, os_type='otherGuest64', description='Linux'), system.operating_system)
        self.assertEqual(1, len(system.products))
        self.assertEqual([], system.products[0].properties)
        self.assertEqual([], system.eulas)

        hardware = self.only_hardware(envelope)
        self.assertEqual(2, hardware.vcpus)
        self.assertEqual(2147483648, hardware.memory_bytes)    # 2048 MegaBytes, 2048 x 2^20
        # The USB controller, resource type 23, and the sound card, resource type 1, are marked not required.
        self.assertEqual([ovf.Controller(instance_id='3', bus='scsi')], hardware.controllers)
        self.assertEqual(
            [ovf.DiskDrive(parent='3', address_on_parent=0, element_name='disk1', host_resource='/disk/vmdisk1')],
            hardware.disk_drives)
        self.assertEqual([ovf.Nic(resource_subtype='E1000', connection='Bridged')], hardware.nics)
        self.assertEqual([], hardware.transport)
        self.assertEqual('vmx-10', hardware.system_type)
        self.assertEqual('Home Assistant', hardware.system_identifier)

    def test_photon_3_0_hw11(self):
        envelope = parse('photon-3.0-hw11')
        self.assertEqual(OVF_1, envelope.namespace)
        self.assertEqual([ovf.File(id='file1', href='photon-ova-disk1.vmdk', size=161960448)], envelope.files)
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', capacity_bytes=17179869184,     # 16 x 2^30
                      file_ref='file1', format=STREAM_OPTIMIZED, populated_size=494862336)],
            envelope.disks)
        self.assertEqual(
            [ovf.Network(name='None', description='The None network')], envelope.networks)
        self.assertEqual([], envelope.deployment_options)

        system = envelope.virtual_system
        self.assertEqual('vm', system.id)
        self.assertEqual('Photon OS', system.name)
        self.assertEqual(ovf.OperatingSystem(id=100, os_type='other3xLinux64Guest'), system.operating_system)
        self.assertEqual(1, len(system.products))
        self.assertEqual('3.0', system.products[0].version)
        self.assertEqual([], system.products[0].properties)
        # License@msgid is VMware's unqualified ovf:msgid; the text is the element's own.
        self.assertEqual(1, len(system.eulas))

        hardware = self.only_hardware(envelope)
        self.assertEqual(1, hardware.vcpus)
        self.assertEqual(2147483648, hardware.memory_bytes)    # 2048 x 2^20
        self.assertEqual(
            [ovf.Controller(instance_id='3', bus='scsi'), ovf.Controller(instance_id='4', bus='ide')],
            hardware.controllers)
        self.assertEqual(
            [ovf.DiskDrive(parent='3', address_on_parent=0, element_name='disk0', host_resource='ovf:/disk/vmdisk1')],
            hardware.disk_drives)
        self.assertEqual([ovf.Nic(resource_subtype='VmxNet3', connection='None')], hardware.nics)
        self.assertEqual('vmx-11', hardware.system_type)
        self.assertEqual('Photon OS', hardware.system_identifier)
        self.assertEqual([], hardware.transport)

    def test_photon_5_0_aarch64_uefi_hw14(self):
        envelope = parse('photon-5.0-aarch64-uefi-hw14')
        self.assertEqual(OVF_1, envelope.namespace)
        self.assertEqual([ovf.File(id='file1', href='photon-disk1.vmdk', size=293515264)], envelope.files)
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', capacity_bytes=17179869184,     # 16 x 2^30
                      file_ref='file1', format=STREAM_OPTIMIZED, populated_size=845414400)],
            envelope.disks)
        self.assertEqual(['bridged'], [network.name for network in envelope.networks])
        self.assertEqual([], envelope.deployment_options)

        system = envelope.virtual_system
        self.assertEqual('vm', system.id)
        self.assertEqual('Photon OS', system.name)
        self.assertEqual(ovf.OperatingSystem(id=36, os_type='vmwarePhoton64Guest'), system.operating_system)
        self.assertEqual(1, len(system.products))
        self.assertEqual('5.0', system.products[0].version)
        self.assertEqual([], system.products[0].properties)
        self.assertEqual(1, len(system.eulas))

        hardware = self.only_hardware(envelope)
        self.assertEqual(1, hardware.vcpus)
        self.assertEqual(2147483648, hardware.memory_bytes)    # 2048 x 2^20
        # Resource type 20 with the subtype vmware.sata.ahci. The USB controller
        # is marked not required and is not a disk controller.
        self.assertEqual([ovf.Controller(instance_id='3', bus='sata')], hardware.controllers)
        self.assertEqual(
            [ovf.DiskDrive(parent='3', address_on_parent=0, element_name='disk0', host_resource='ovf:/disk/vmdisk1')],
            hardware.disk_drives)
        self.assertEqual([ovf.Nic(resource_subtype='VmxNet3', connection='bridged')], hardware.nics)
        self.assertEqual('vmx-14', hardware.system_type)
        self.assertEqual([], hardware.transport)

    def test_remnux_202610b(self):
        envelope = parse('remnux-202610b')
        self.assertEqual(OVF_1, envelope.namespace)
        self.assertEqual(
            [ovf.File(id='file1', href='remnux-noble-amd64-disk1.vmdk.gz', size=8304866124, compression='gzip')],
            envelope.files)
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', capacity_bytes=107374182400,    # 100 x 2^30
                      file_ref='file1', format=STREAM_OPTIMIZED, populated_size=21506097152)],
            envelope.disks)
        self.assertEqual(['nat'], [network.name for network in envelope.networks])
        self.assertEqual([], envelope.deployment_options)

        system = envelope.virtual_system
        self.assertEqual('vm', system.id)
        self.assertEqual('REMnux', system.name)
        self.assertEqual(ovf.OperatingSystem(id=94, os_type='ubuntu64Guest'), system.operating_system)
        self.assertEqual([], system.products)
        self.assertEqual([], system.eulas)

        hardware = self.only_hardware(envelope)
        self.assertEqual(2, hardware.vcpus)
        self.assertEqual(4294967296, hardware.memory_bytes)    # 4096 x 2^20
        # The disk sits on the SCSI controller, not the SATA one, which holds
        # only the CD-ROM.
        self.assertEqual(
            [ovf.Controller(instance_id='3', bus='sata'), ovf.Controller(instance_id='5', bus='scsi')],
            hardware.controllers)
        self.assertEqual(
            [ovf.DiskDrive(parent='5', address_on_parent=0, element_name='disk0', host_resource='ovf:/disk/vmdisk1')],
            hardware.disk_drives)
        self.assertEqual([ovf.Nic(resource_subtype='E1000', connection='nat')], hardware.nics)
        self.assertEqual('vmx-14', hardware.system_type)
        self.assertEqual('REMnux', hardware.system_identifier)

    def test_talos_1_14_3(self):
        envelope = parse('talos-1.14.3')
        self.assertEqual(OVF_1, envelope.namespace)
        self.assertEqual([ovf.File(id='file1', href='disk.vmdk', size=233791488)], envelope.files)
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', capacity_bytes=11736711168,     # 11193 x 2^20
                      file_ref='file1', format=STREAM_OPTIMIZED)],
            envelope.disks)
        self.assertEqual(['VM Network'], [network.name for network in envelope.networks])
        self.assertEqual([], envelope.deployment_options)

        system = envelope.virtual_system
        self.assertEqual('vm', system.id)
        self.assertEqual('talos', system.name)
        self.assertEqual(ovf.OperatingSystem(id=101, os_type='other3xLinux64Guest'), system.operating_system)
        self.assertEqual(1, len(system.products))
        self.assertEqual(1, len(system.products[0].properties))
        prop = system.products[0].properties[0]
        self.assertEqual('talos.config', prop.key)
        self.assertEqual('string', prop.type)
        self.assertTrue(prop.user_configurable)
        self.assertFalse(prop.password)
        self.assertEqual('', prop.value)
        self.assertEqual([], system.eulas)

        hardware = self.only_hardware(envelope)
        self.assertEqual(2, hardware.vcpus)
        self.assertEqual(2147483648, hardware.memory_bytes)    # 2048 x 2^20
        self.assertEqual([ovf.Controller(instance_id='3', bus='scsi')], hardware.controllers)
        self.assertEqual(
            [ovf.DiskDrive(parent='3', address_on_parent=0, element_name='disk0', host_resource='ovf:/disk/vmdisk1')],
            hardware.disk_drives)
        self.assertEqual([ovf.Nic(resource_subtype='VmxNet3', connection='VM Network')], hardware.nics)
        self.assertEqual('vmx-15', hardware.system_type)
        self.assertEqual(['com.vmware.guestInfo'], hardware.transport)

    def test_ubuntu_24_04_20260926(self):
        envelope = parse('ubuntu-24.04-20260926')
        self.assertEqual(OVF_1, envelope.namespace)
        self.assertEqual(
            [ovf.File(id='file1', href='ubuntu-noble-24.04-cloudimg.vmdk', size=594777600)], envelope.files)
        # capacityAllocationUnits="byte", which once failed to parse.
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', capacity_bytes=10737418240, file_ref='file1', format=STREAM_OPTIMIZED,
                      populated_size=0)],
            envelope.disks)
        self.assertEqual(['VM Network'], [network.name for network in envelope.networks])
        self.assertEqual([], envelope.deployment_options)

        system = envelope.virtual_system
        self.assertEqual('ubuntu-noble-24.04-cloudimg-20260926', system.id)
        self.assertEqual('ubuntu-noble-24.04-cloudimg-20260926', system.name)
        self.assertEqual(
            ovf.OperatingSystem(id=94, os_type='ubuntu64Guest', description='Ubuntu Linux (64-bit)'),
            system.operating_system)

        # cloud-init's OVF datasource properties. seedfrom has no ovf:value at
        # all; the rest have one, some of them empty.
        self.assertEqual(1, len(system.products))
        product = system.products[0]
        self.assertIsNone(product.version)
        self.assertEqual(
            [('instance-id', 'id-ovf'), ('hostname', 'ubuntuguest'), ('seedfrom', None), ('public-keys', ''),
             ('user-data', ''), ('password', '')],
            [(prop.key, prop.value) for prop in product.properties])
        self.assertTrue(all(prop.user_configurable for prop in product.properties))
        # The property keyed password does not carry ovf:password.
        self.assertFalse(any(prop.password for prop in product.properties))
        # hostname has a Description and no Label.
        self.assertIsNone(product.properties[1].label)
        self.assertEqual([], system.eulas)

        hardware = self.only_hardware(envelope)
        self.assertEqual(2, hardware.vcpus)
        self.assertEqual(1073741824, hardware.memory_bytes)    # 1024 x 2^20
        # The serial port, resource type 21, is marked not required and passed over.
        self.assertEqual(
            [ovf.Controller(instance_id='3', bus='scsi'),
             ovf.Controller(instance_id='5', bus='ide'),
             ovf.Controller(instance_id='6', bus='ide')],
            hardware.controllers)
        self.assertEqual(
            [ovf.DiskDrive(parent='3', address_on_parent=0, element_name='Hard Disk 1',
                           host_resource='ovf:/disk/vmdisk1')],
            hardware.disk_drives)
        self.assertEqual([ovf.Nic(resource_subtype='VmxNet3', connection='VM Network')], hardware.nics)
        self.assertEqual('vmx-10', hardware.system_type)
        self.assertEqual(['iso'], hardware.transport)

    def test_vulnhub_blogger(self):
        envelope = parse('vulnhub-blogger')
        self.assertEqual(OVF_1, envelope.namespace)
        self.assertEqual('1.0', envelope.version)
        self.assertEqual(
            [ovf.File(id='file1', href='blogger-disk001.vmdk'), ovf.File(id='file2', href='blogger-disk002.vmdk')],
            envelope.files)
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', capacity_bytes=10737418240, file_ref='file1', format=STREAM_OPTIMIZED),
             ovf.Disk(disk_id='vmdisk2', capacity_bytes=10485760, file_ref='file2', format=STREAM_OPTIMIZED)],
            envelope.disks)
        self.assertEqual(['HostOnly', 'NAT'], [network.name for network in envelope.networks])
        self.assertEqual([], envelope.deployment_options)

        system = envelope.virtual_system
        self.assertEqual('Blogger', system.id)
        self.assertEqual(ovf.OperatingSystem(id=94, description='Ubuntu_64'), system.operating_system)
        self.assertEqual(1, len(system.products))
        self.assertEqual([], system.products[0].properties)
        self.assertEqual([], system.eulas)

        hardware = self.only_hardware(envelope)
        self.assertEqual(2, hardware.vcpus)
        self.assertEqual(1073741824, hardware.memory_bytes)    # 1024 MegaBytes, 1024 x 2^20
        self.assertEqual(
            [ovf.Controller(instance_id='3', bus='ide'),
             ovf.Controller(instance_id='4', bus='ide'),
             ovf.Controller(instance_id='5', bus='scsi')],
            hardware.controllers)
        self.assertEqual(
            [ovf.DiskDrive(parent='5', address_on_parent=0, element_name='disk1', host_resource='/disk/vmdisk1'),
             ovf.DiskDrive(parent='5', address_on_parent=1, element_name='disk2', host_resource='/disk/vmdisk2')],
            hardware.disk_drives)
        self.assertEqual(
            [ovf.Nic(resource_subtype='E1000', connection='NAT'),
             ovf.Nic(resource_subtype='E1000', connection='HostOnly')],
            hardware.nics)
        self.assertEqual('virtualbox-2.2', hardware.system_type)
        self.assertEqual('Blogger', hardware.system_identifier)

    def test_vyos_1_2_1(self):
        # Three deployment options, with ovftool's unqualified configuration
        # attribute on the CPU and memory items.
        envelope = parse('vyos-1.2.1')
        self.assertEqual(OVF_1, envelope.namespace)
        self.assertEqual([ovf.File(id='file1', href='vyos-1.2.1-disk1.vmdk', size=429361664)], envelope.files)
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', capacity_bytes=10737418240,     # 10 x 2^30
                      file_ref='file1', format=STREAM_OPTIMIZED, populated_size=439156736)],
            envelope.disks)
        self.assertEqual(
            [ovf.Network(name='LAN', description='LAN network'), ovf.Network(name='WAN', description='WAN network')],
            envelope.networks)
        self.assertEqual(
            [('1CPU-512MB', True, 'TRIMMED', 'TRIMMED'), ('4CPU-16GB', False, 'TRIMMED', 'TRIMMED'),
             ('8CPU-32GB', False, 'TRIMMED', 'TRIMMED')],
            [(option.id, option.default, option.label, option.description) for option in envelope.deployment_options])

        system = envelope.virtual_system
        self.assertEqual('VyOS', system.id)
        self.assertIsNone(system.name)
        self.assertEqual(
            ovf.OperatingSystem(
                id=96, version='6', os_type='debian8_64Guest', description='Debian GNU/Linux 8 (64-bit)'),
            system.operating_system)

        self.assertEqual(2, len(system.products))
        appliance, vm = system.products
        self.assertIsNone(appliance.product_class)
        self.assertEqual('1.2.1', appliance.version)
        self.assertIsNone(appliance.app_url)                    # <AppUrl/> is empty
        self.assertEqual(
            ['password', 'public-keys', 'local-hostname', 'ip0', 'netmask0', 'gateway', 'DNS', 'NTP'],
            [prop.key for prop in appliance.properties])
        password = appliance.properties[0]
        self.assertTrue(password.password)
        self.assertEqual('MinLen(8)', password.qualifiers)
        self.assertEqual('', password.value)
        self.assertEqual('MinLen(0),MaxLen(65535)', appliance.properties[2].qualifiers)
        self.assertEqual([None] * 5, [prop.value for prop in appliance.properties[3:]])
        self.assertEqual([False] * 7, [prop.password for prop in appliance.properties[1:]])
        self.assertTrue(all(prop.user_configurable for prop in appliance.properties))
        self.assertEqual('vm', vm.product_class)
        self.assertEqual(1, len(vm.properties))
        self.assertEqual(('vmname', 'VyOS', False), (vm.properties[0].key, vm.properties[0].value,
                                                     vm.properties[0].user_configurable))
        self.assertEqual([], system.eulas)

        # The default configuration is 1CPU-512MB: one vCPU and 512 MiB.
        hardware = self.only_hardware(envelope)
        self.assertEqual(1, hardware.vcpus)
        self.assertEqual(536870912, hardware.memory_bytes)     # 512 x 2^20
        self.assertEqual(
            [ovf.Controller(instance_id='3', bus='scsi'), ovf.Controller(instance_id='5', bus='ide')],
            hardware.controllers)
        # The CD/DVD drive on controller 5 is resource type 15, not a disk drive.
        self.assertEqual(
            [ovf.DiskDrive(parent='3', address_on_parent=0, element_name='disk0', host_resource='ovf:/disk/vmdisk1')],
            hardware.disk_drives)
        self.assertEqual(
            [ovf.Nic(resource_subtype='vmxnet3', connection='LAN'),
             ovf.Nic(resource_subtype='vmxnet3', connection='WAN')],
            hardware.nics)
        self.assertEqual('vmx-11', hardware.system_type)
        self.assertIsNone(hardware.system_identifier)
        self.assertEqual(['com.vmware.guestInfo'], hardware.transport)

    def test_wazuh_4_9_1(self):
        envelope = parse('wazuh-4.9.1')
        self.assertEqual(OVF_1, envelope.namespace)
        self.assertEqual([ovf.File(id='file1', href='wazuh-4.9.1-disk-1.vmdk', size=3950369280)], envelope.files)
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', capacity_bytes=53687091200,     # 50 x 2^30
                      file_ref='file1', format=STREAM_OPTIMIZED)],
            envelope.disks)
        self.assertEqual(['VM Network'], [network.name for network in envelope.networks])
        self.assertEqual([], envelope.deployment_options)

        system = envelope.virtual_system
        self.assertEqual('Wazuh v4.9.1 OVA', system.id)
        self.assertEqual(
            ovf.OperatingSystem(id=101, os_type='otherLinux64Guest', description='Linux - Amazon Linux 2'),
            system.operating_system)
        self.assertEqual(1, len(system.products))
        self.assertEqual('4.9.1', system.products[0].version)
        self.assertEqual([], system.products[0].properties)
        self.assertEqual([], system.eulas)

        hardware = self.only_hardware(envelope)
        self.assertEqual(4, hardware.vcpus)
        self.assertEqual(8589934592, hardware.memory_bytes)    # 8192 x 2^20
        self.assertEqual(
            [ovf.Controller(instance_id='3', bus='ide'), ovf.Controller(instance_id='4', bus='ide')],
            hardware.controllers)
        # The disk is on IDE controller 0, InstanceID 4; the CD-ROM is on controller 3.
        self.assertEqual(
            [ovf.DiskDrive(parent='4', address_on_parent=0, element_name='Hard Disk 1',
                           host_resource='ovf:/disk/vmdisk1')],
            hardware.disk_drives)
        self.assertEqual([ovf.Nic(resource_subtype='E1000', connection='VM Network')], hardware.nics)
        self.assertEqual('vmx-07', hardware.system_type)
        self.assertEqual('wazuh-4.9.1', hardware.system_identifier)

    def test_every_vendor_fixture_that_parses_has_a_test(self):
        # A vendor fixture whose expected file is a model must have a test above.
        parsing = []
        for filename in os.listdir(VENDOR):
            if filename.endswith('.ovf'):
                name = filename[:-len('.ovf')]
                try:
                    parse(name)
                except ovf.OVFError:
                    continue
                parsing.append('test_' + name.replace('.', '_').replace('-', '_'))
        self.assertNotEqual([], parsing)
        missing = [name for name in parsing if not hasattr(self, name)]
        self.assertEqual([], sorted(missing))
