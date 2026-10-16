"""The descriptor parser's rules, each on a small descriptor written to exercise it.

descriptor() builds a valid descriptor, and each test replaces one part of it.
The golden tests in test_ovf_golden.py cover whole fixtures.
"""

import os
import re
from unittest import mock

import defusedxml
import testtools

from shakenfist_client_ova import ovf
from shakenfist_client_ova.ovf import namespaces


FIXTURES = os.path.join(os.path.dirname(__file__), 'fixtures', 'ovf')

EXT = 'http://example.org/ovf/extension/1'

TEMPLATE = '''<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="{namespace}" xmlns:ovf="{namespace}"
          xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
          xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
          xmlns:sasd="{sasd}"
          xmlns:epasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_EthernetPortAllocationSettingData"
          xmlns:vmw="http://www.vmware.com/schema/ovf"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xmlns:ext="{ext}"{envelope_attributes}>
  <References>{files}</References>
  <DiskSection>
    <Info>Virtual disk information</Info>{disks}
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>{networks}
  </NetworkSection>{envelope_sections}
  <VirtualSystem ovf:id="vm"{system_attributes}>
    <Info>A virtual machine</Info>{system_sections}
    <VirtualHardwareSection{hardware_attributes}>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemType>vmx-13</vssd:VirtualSystemType>{system}
      </System>{items}
    </VirtualHardwareSection>{hardware_sections}
  </VirtualSystem>{trailer}
</Envelope>
'''


def item(resource_type, *properties, **kwargs):
    """A hardware item: properties are (name, text) pairs in the item's CIM namespace."""
    element = kwargs.get('element', 'Item')
    cim = {'Item': 'rasd', 'StorageItem': 'sasd', 'EthernetPortItem': 'epasd'}[element]
    body = ''.join('<%s:%s>%s</%s:%s>' % (cim, name, text, cim, name) for name, text in properties)
    if resource_type is not None:
        body += '<%s:ResourceType>%s</%s:ResourceType>' % (cim, resource_type, cim)
    return '\n      <%s%s>%s%s</%s>' % (element, kwargs.get('attributes', ''), body, kwargs.get('extra', ''), element)


CPU = item(3, ('AllocationUnits', 'hertz * 10^6'), ('ElementName', '2 virtual CPUs'), ('InstanceID', '1'),
           ('VirtualQuantity', '2'))
MEMORY = item(4, ('AllocationUnits', 'byte * 2^20'), ('ElementName', '1024MB of memory'), ('InstanceID', '2'),
              ('VirtualQuantity', '1024'))
SCSI = item(6, ('InstanceID', '3'), ('ResourceSubType', 'lsilogic'))
DISK = item(17, ('AddressOnParent', '0'), ('ElementName', 'Hard disk 1'), ('HostResource', 'ovf:/disk/vmdisk1'),
            ('InstanceID', '4'), ('Parent', '3'))
NIC = item(10, ('Connection', 'net'), ('ElementName', 'Network adapter 1'), ('InstanceID', '5'),
           ('ResourceSubType', 'E1000'))

DEFAULTS = {
    'namespace': namespaces.OVF_1,
    'sasd': namespaces.SASD,
    'ext': EXT,
    'envelope_attributes': ' ovf:version="1.0"',
    'files': '\n    <File ovf:id="file1" ovf:href="disk1.vmdk"/>',
    'disks': ('\n    <Disk ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:capacity="1" '
              'ovf:capacityAllocationUnits="byte * 2^30"/>'),
    'networks': '\n    <Network ovf:name="net"/>',
    'envelope_sections': '',
    'system_attributes': '',
    'system_sections': '',
    'hardware_attributes': '',
    'system': '',
    'items': CPU + MEMORY + SCSI + DISK + NIC,
    'hardware_sections': '',
    'trailer': '',
}


def descriptor(**parts):
    """A small valid descriptor's bytes, with any of DEFAULTS' parts replaced."""
    for name in parts:
        if name not in DEFAULTS:
            raise ValueError('No descriptor part is called %s' % name)
    values = dict(DEFAULTS)
    values.update(parts)
    return TEMPLATE.format(**values).encode('utf-8')


def parse(**parts):
    return ovf.parse_descriptor(descriptor(**parts))


DEPLOYMENT_OPTIONS = '''
  <DeploymentOptionSection>
    <Info>The list of deployment options</Info>
    <Configuration ovf:id="small">
      <Label>Small</Label>
      <Description>One CPU</Description>
    </Configuration>
    <Configuration ovf:id="large" ovf:default="true">
      <Label>Large</Label>
      <Description>Four CPUs</Description>
    </Configuration>
    <Configuration ovf:id="huge">
      <Label>Huge</Label>
      <Description>Eight CPUs</Description>
    </Configuration>
  </DeploymentOptionSection>'''


class DescriptorTestCase(testtools.TestCase):
    def assertRefused(self, cls, fragment, data):
        """Assert that parsing data raises cls with a message containing fragment, and return the exception."""
        e = self.assertRaises(cls, ovf.parse_descriptor, data)
        self.assertIn(fragment, str(e))
        # Every refusal is named by the parser, never by a library's exception.
        self.assertEqual(cls.__name__, ovf.outcome_name(e))
        return e

    def assertUnread(self, paths, data):
        """Assert that data is refused for exactly these unread paths."""
        e = self.assertRefused(ovf.UnparsedContentError, 'does not understand', data)
        lines = str(e).split('\n')
        self.assertEqual('The descriptor has content the parser does not understand:', lines[0])
        self.assertEqual(['    ' + path for path in paths], lines[1:])


class BasicsTestCase(DescriptorTestCase):
    def test_template_parses(self):
        envelope = parse()
        self.assertEqual(namespaces.OVF_1, envelope.namespace)
        self.assertEqual('1.0', envelope.version)
        self.assertEqual([ovf.File(id='file1', href='disk1.vmdk')], envelope.files)
        self.assertEqual([ovf.Disk(disk_id='vmdisk1', file_ref='file1', capacity_bytes=2 ** 30)], envelope.disks)
        self.assertEqual([ovf.Network(name='net')], envelope.networks)
        self.assertEqual('vm', envelope.virtual_system.id)
        self.assertEqual(
            [ovf.VirtualHardware(
                vcpus=2, memory_bytes=2 ** 30, system_type='vmx-13',
                controllers=[ovf.Controller(instance_id='3', bus='scsi')],
                disk_drives=[ovf.DiskDrive(parent='3', address_on_parent=0, element_name='Hard disk 1',
                                           host_resource='ovf:/disk/vmdisk1')],
                nics=[ovf.Nic(resource_subtype='E1000', connection='net')])],
            envelope.virtual_system.hardware)

    def test_ovf_2_is_read_by_the_same_lookups(self):
        one = parse()
        two = parse(namespace=namespaces.OVF_2, envelope_attributes=' ovf:version="2.0"')
        self.assertEqual(namespaces.OVF_2, two.namespace)
        two.namespace, two.version = one.namespace, one.version
        self.assertEqual(ovf.to_json(one), ovf.to_json(two))

    def test_ovf_2_items(self):
        items = (CPU + MEMORY + SCSI
                 + item(17, ('AddressOnParent', '0'), ('HostResource', 'ovf:/disk/vmdisk1'), ('Parent', '3'),
                        element='StorageItem')
                 + item(10, ('Connection', 'net'), ('ResourceSubType', 'VirtIO'), element='EthernetPortItem'))
        hardware = parse(namespace=namespaces.OVF_2, items=items).virtual_system.hardware[0]
        self.assertEqual([ovf.DiskDrive(parent='3', address_on_parent=0, host_resource='ovf:/disk/vmdisk1')],
                         hardware.disk_drives)
        self.assertEqual([ovf.Nic(resource_subtype='VirtIO', connection='net')], hardware.nics)

    def test_virtualbox_suffixed_namespace_is_read_as_the_dmtf_one(self):
        items = (CPU + MEMORY + SCSI + NIC
                 + item(17, ('AddressOnParent', '0'), ('Parent', '3'), element='StorageItem'))
        envelope = parse(namespace=namespaces.OVF_2, sasd=namespaces.VIRTUALBOX_SASD, items=items)
        self.assertEqual('3', envelope.virtual_system.hardware[0].disk_drives[0].parent)

    def test_instance_id_is_read_as_instance_id(self):
        items = CPU + MEMORY + item(6, ('InstanceId', '3')) + DISK
        self.assertEqual([ovf.Controller(instance_id='3', bus='scsi')],
                         parse(items=items).virtual_system.hardware[0].controllers)

    def test_every_hardware_section_is_read_in_order(self):
        second = '''
    <VirtualHardwareSection>
      <Info>A second family</Info>%s
    </VirtualHardwareSection>''' % item(3, ('VirtualQuantity', '8'))
        hardware = parse(hardware_sections=second).virtual_system.hardware
        self.assertEqual([2, 8], [h.vcpus for h in hardware])

    def test_transport_and_system(self):
        hardware = parse(hardware_attributes=' ovf:transport="com.vmware.guestInfo iso"',
                         system='<vssd:VirtualSystemIdentifier>vm</vssd:VirtualSystemIdentifier>')
        hardware = hardware.virtual_system.hardware[0]
        self.assertEqual((['com.vmware.guestInfo', 'iso'], 'vmx-13', 'vm'),
                         (hardware.transport, hardware.system_type, hardware.system_identifier))

    def test_file_attributes(self):
        files = '<File ovf:id="file1" ovf:href="disk1.vmdk" ovf:size="10" ovf:compression="gzip" ovf:chunkSize="5"/>'
        self.assertEqual([ovf.File(id='file1', href='disk1.vmdk', size=10, compression='gzip', chunk_size=5)],
                         parse(files=files).files)

    def test_disk_attributes(self):
        disks = ('<Disk ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:capacity="1" ovf:format="vmdk" '
                 'ovf:populatedSize="7"/><Disk ovf:diskId="delta" ovf:capacity="1" ovf:parentRef="vmdisk1"/>')
        self.assertEqual(
            [ovf.Disk(disk_id='vmdisk1', file_ref='file1', capacity_bytes=1, format='vmdk', populated_size=7),
             ovf.Disk(disk_id='delta', capacity_bytes=1, parent_ref='vmdisk1')],
            parse(disks=disks).disks)

    def test_empty_references_and_no_disk_or_network_section(self):
        data = descriptor(files='', disks='', items=CPU + MEMORY)
        data = re.sub(rb'<DiskSection>.*?</DiskSection>|<NetworkSection>.*?</NetworkSection>', b'', data, flags=re.S)
        envelope = ovf.parse_descriptor(data)
        self.assertEqual(([], [], []), (envelope.files, envelope.disks, envelope.networks))


class EnvelopeTestCase(DescriptorTestCase):
    def test_ovf_0_9(self):
        self.assertRefused(ovf.UnsupportedEnvelopeError, 'OVF 0.9 envelope',
                           descriptor(namespace=namespaces.OVF_0_9))

    def test_no_namespace(self):
        data = descriptor().replace(b'xmlns="%s" ' % namespaces.OVF_1.encode('utf-8'), b'')
        self.assertRefused(ovf.UnsupportedEnvelopeError, 'root element Envelope is in no namespace', data)

    def test_unknown_namespace(self):
        self.assertRefused(ovf.UnsupportedEnvelopeError, 'in the namespace http://schemas.dmtf.org/ovf/envelope/3',
                           descriptor(namespace='http://schemas.dmtf.org/ovf/envelope/3'))

    def test_root_is_not_envelope(self):
        data = b'<ovf:References xmlns:ovf="%s"/>' % namespaces.OVF_1.encode('utf-8')
        self.assertRefused(ovf.UnsupportedEnvelopeError, 'but is not Envelope', data)

    def test_virtual_system_collection_is_refused_before_anything_else(self):
        data = ('<Envelope xmlns="%s"><VirtualSystemCollection ovf:id="x" xmlns:ovf="%s"/><Unknown/></Envelope>'
                % (namespaces.OVF_1, namespaces.OVF_1)).encode('utf-8')
        self.assertRefused(ovf.VirtualSystemCollectionError, 'VirtualSystemCollection', data)

    def test_no_virtual_system(self):
        data = re.sub(rb'<VirtualSystem .*</VirtualSystem>', b'', descriptor(), flags=re.S)
        self.assertRefused(ovf.MissingContentError, 'Envelope has no VirtualSystem', data)

    def test_no_references(self):
        data = re.sub(rb'<References>.*</References>', b'', descriptor(), flags=re.S)
        self.assertRefused(ovf.MissingContentError, 'Envelope has no References', data)

    def test_no_hardware_section(self):
        data = re.sub(rb'<VirtualHardwareSection.*</VirtualHardwareSection>', b'', descriptor(), flags=re.S)
        self.assertRefused(ovf.MissingContentError, 'Envelope/VirtualSystem has no VirtualHardwareSection', data)

    def test_required_attributes(self):
        for parts, fragment in (
                ({'files': '<File ovf:id="file1"/>'}, 'Envelope/References/File has no ovf:href'),
                ({'files': '<File ovf:href="disk1.vmdk"/>'}, 'Envelope/References/File has no ovf:id'),
                ({'disks': '<Disk ovf:capacity="1"/>'}, 'Envelope/DiskSection/Disk has no ovf:diskId'),
                ({'disks': '<Disk ovf:diskId="vmdisk1"/>'}, 'Envelope/DiskSection/Disk has no ovf:capacity'),
                ({'networks': '<Network/>'}, 'Envelope/NetworkSection/Network has no ovf:name'),
                ({'items': CPU + item(None, ('VirtualQuantity', '1'))},
                 'Envelope/VirtualSystem/VirtualHardwareSection/Item[2] has no rasd:ResourceType'),
                ({'items': item(3)}, 'VirtualHardwareSection/Item has no rasd:VirtualQuantity'),
                ({'items': SCSI + item(17, ('AddressOnParent', '0'))}, 'Item[2] has no rasd:Parent'),
                ({'items': SCSI + item(17, ('Parent', '3'))}, 'Item[2] has no rasd:AddressOnParent'),
                ({'items': item(5)}, 'VirtualHardwareSection/Item has no rasd:InstanceID'),
                ({'items': item(5, ('InstanceID', ' '))}, 'VirtualHardwareSection/Item/rasd:InstanceID is empty')):
            self.assertRefused(ovf.MissingContentError, fragment, descriptor(**parts))
        data = descriptor().replace(b'<VirtualSystem ovf:id="vm">', b'<VirtualSystem>')
        self.assertRefused(ovf.MissingContentError, 'Envelope/VirtualSystem has no ovf:id', data)

    def test_invalid_values(self):
        for parts, fragment in (
                ({'files': '<File ovf:id="file1" ovf:href="d" ovf:size="-2"/>'},
                 'Envelope/References/File@ovf:size is "-2", which is not a non-negative integer'),
                ({'disks': '<Disk ovf:diskId="vmdisk1" ovf:capacity="ten"/>'}, '@ovf:capacity is "ten"'),
                ({'items': item(3, ('VirtualQuantity', '1.5'))}, 'rasd:VirtualQuantity is "1.5"'),
                ({'items': item('three', ('VirtualQuantity', '1'))}, 'rasd:ResourceType is "three"'),
                ({'items': item(3, ('VirtualQuantity', '1'), attributes=' ovf:required="no"')},
                 'Item@ovf:required is "no", which is neither true nor false')):
            self.assertRefused(ovf.InvalidValueError, fragment, descriptor(**parts))


class XmlTestCase(DescriptorTestCase):
    def test_not_well_formed(self):
        e = self.assertRefused(ovf.MalformedDescriptorError, 'not well-formed XML', b'<Envelope>\n<a></b>')
        self.assertEqual('The descriptor is not well-formed XML: the first error is at line 2, column 5', str(e))

    def test_empty(self):
        self.assertRefused(ovf.MalformedDescriptorError, 'not well-formed XML', b'')

    def test_entity_declaration(self):
        with open(os.path.join(FIXTURES, 'handwritten', 'entity-declaration.ovf'), 'rb') as f:
            data = f.read()
        e = self.assertRefused(ovf.EntityDeclarationError, 'declares an entity, "vmname"', data)
        self.assertNotIn('EntitiesForbidden', str(e))

    def test_external_entity_declaration(self):
        data = b'<!DOCTYPE Envelope [<!ENTITY e SYSTEM "http://example.com/e">]><Envelope>&e;</Envelope>'
        self.assertRefused(ovf.EntityDeclarationError, 'declares an entity, "e"', data)

    def test_each_defusedxml_refusal(self):
        for exception, fragment in (
                (defusedxml.EntitiesForbidden('e', 'x', None, None, None, None), 'declares an entity, "e"'),
                (defusedxml.ExternalReferenceForbidden(None, None, 'http://example.com/e', None),
                 'refers to an external entity'),
                (defusedxml.DTDForbidden('Envelope', None, None), 'declares a document type')):
            with mock.patch('shakenfist_client_ova.ovf.descriptor.ElementTree.iterparse', side_effect=exception):
                e = self.assertRefused(ovf.EntityDeclarationError, fragment, b'<Envelope/>')
            self.assertNotIn(type(exception).__name__, str(e))

    def test_unreadable_encodings(self):
        for encoding in (b'bogus', b'shift_jis', b'rot13'):
            data = b'<?xml version="1.0" encoding="%s"?><Envelope/>' % encoding
            self.assertRefused(ovf.MalformedDescriptorError, 'character encoding', data)


class StrictnessTestCase(DescriptorTestCase):
    def test_unread_required_element(self):
        self.assertUnread(['Envelope/VirtualSystem/ext:Section'],
                          descriptor(system_sections='<ext:Section><ext:Inner/></ext:Section>'))
        self.assertUnread(['Envelope/VirtualSystem/InstallSection'],
                          descriptor(system_sections='<InstallSection><Info>x</Info></InstallSection>'))

    def test_unread_subtree_is_reported_once_at_its_root(self):
        section = '<ext:Section ovf:bogus="1"><ext:Inner ovf:bogus="1"><ext:Deeper/></ext:Inner></ext:Section>'
        self.assertUnread(['Envelope/ext:Section'], descriptor(envelope_sections=section))

    def test_required_false_subtree_is_ignored(self):
        section = ('<ext:Section ovf:required="false"><Info>x</Info><ext:Inner ovf:bogus="1"/><Unknown/>'
                   '</ext:Section>')
        parse(envelope_sections=section, system_sections=section,
              items=CPU + MEMORY + item(15, extra='<ext:Config ovf:required="false"/>'))

    def test_required_false_on_a_read_element_ignores_what_is_not_understood_inside_it(self):
        product = '<ProductSection ovf:required="false"><Product>x</Product><ext:Unknown/></ProductSection>'
        envelope = parse(system_sections=product, hardware_attributes=' ovf:required="false"',
                         items=CPU + MEMORY + '<vmw:Config vmw:key="firmware" vmw:value="efi"/>')
        self.assertEqual('x', envelope.virtual_system.products[0].product)
        self.assertUnread(['Envelope/VirtualSystem/ProductSection/ext:Unknown'],
                          descriptor(system_sections=product.replace(' ovf:required="false"', '')))

    def test_required_true_is_refused(self):
        self.assertUnread(['Envelope/ext:Section'],
                          descriptor(envelope_sections='<ext:Section ovf:required="true"/>'))

    def test_custom_namespace_attributes_are_ignored(self):
        parse(envelope_attributes=' ovf:version="1.0" ext:a="1" vmw:buildId="build-1"',
              system_attributes=' ext:a="1"',
              disks='<Disk ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:capacity="1" ext:uuid="x"/>',
              items=CPU + MEMORY + item(15, attributes=' ext:a="1"'))

    def test_ovf_and_cim_namespace_attributes_are_refused(self):
        self.assertUnread(
            ['Envelope/DiskSection/Disk@ovf:boot',
             'Envelope/VirtualSystem/VirtualHardwareSection/Item/rasd:ElementName@rasd:bogus'],
            descriptor(disks='<Disk ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:capacity="1" ovf:boot="true"/>',
                       items=item(3, ('VirtualQuantity', '1'),
                                  extra='<rasd:ElementName rasd:bogus="1">CPU</rasd:ElementName>')))

    def test_unqualified_attribute_is_read_as_the_ovf_one(self):
        items = (item(3, ('VirtualQuantity', '1'), attributes=' configuration="small"')
                 + item(3, ('VirtualQuantity', '4'), attributes=' configuration="large"'))
        self.assertEqual(4, parse(envelope_sections=DEPLOYMENT_OPTIONS, items=items).virtual_system.hardware[0].vcpus)

    def test_unqualified_attribute_not_read_is_refused(self):
        self.assertUnread(
            ['Envelope/DiskSection/Disk@boot', 'Envelope/VirtualSystem@bogus'],
            descriptor(disks='<Disk ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:capacity="1" boot="true"/>',
                       system_attributes=' bogus="1"'))

    def test_both_forms_of_an_attribute_are_refused(self):
        items = item(3, ('VirtualQuantity', '1'), attributes=' ovf:configuration="large" configuration="large"')
        self.assertRefused(
            ovf.UnparsedContentError,
            'Envelope/VirtualSystem/VirtualHardwareSection/Item carries ovf:configuration more than once',
            descriptor(envelope_sections=DEPLOYMENT_OPTIONS, items=items))

    def test_strings_and_msgid_are_ignored(self):
        strings = '''
  <Strings xml:lang="fr">
    <Msg ovf:msgid="label">Petit</Msg>
  </Strings>'''
        options = DEPLOYMENT_OPTIONS.replace('<Label>Small</Label>', '<Label ovf:msgid="label">Small</Label>')
        eula = '<EulaSection><Info>x</Info><License msgid="eula">Some terms</License></EulaSection>'
        envelope = parse(envelope_sections=options, system_sections=eula, trailer=strings)
        self.assertEqual('Small', envelope.deployment_options[0].label)
        self.assertEqual('Some terms', envelope.virtual_system.eulas[0].license)

    def test_info_annotation_and_attributes_without_data_are_ignored(self):
        parse(envelope_attributes=' ovf:version="1.0" xml:lang="en-US" xsi:schemaLocation="a b"',
              system_sections='<AnnotationSection><Info>x</Info><Annotation>Note</Annotation></AnnotationSection>')

    def test_second_singleton_section_is_unread(self):
        os_section = '<OperatingSystemSection ovf:id="36"><Info>x</Info></OperatingSystemSection>'
        self.assertUnread(['Envelope/VirtualSystem/OperatingSystemSection[2]'],
                          descriptor(system_sections=os_section * 2))

    def test_message_is_sorted_and_capped(self):
        sections = ''.join('<ext:Section%02d/>' % n for n in range(25, 0, -1))
        e = self.assertRefused(ovf.UnparsedContentError, 'does not understand', descriptor(envelope_sections=sections))
        lines = str(e).split('\n')
        self.assertEqual(
            ['The descriptor has content the parser does not understand:']
            + ['    Envelope/ext:Section%02d' % n for n in range(1, 21)]
            + ['    ... and 5 more'],
            lines)

    def test_repeated_names_are_numbered(self):
        self.assertUnread(['Envelope/ext:Section[1]', 'Envelope/ext:Section[2]'],
                          descriptor(envelope_sections='<ext:Section/><ext:Section/>'))

    def test_unprefixed_custom_namespace_is_named_by_uri(self):
        self.assertUnread(['Envelope/VirtualSystem/{http://example.org/other}Section'],
                          descriptor(system_sections='<Section xmlns="http://example.org/other"/>'))


class CimTestCase(DescriptorTestCase):
    def test_read_properties_are_read_on_every_item(self):
        # ElementName and AllocationUnits on a CPU item, VirtualQuantityUnits
        # of count, and HostResource on a NIC and a CD drive, none of which
        # the parser uses there.
        items = (item(3, ('AllocationUnits', 'hertz * 10^6'), ('ElementName', 'CPU'), ('InstanceID', '1'),
                      ('VirtualQuantity', '2'), ('VirtualQuantityUnits', 'count'))
                 + MEMORY + SCSI + DISK
                 + item(10, ('Connection', 'net'), ('HostResource', 'ovf:/network/net'), ('InstanceID', '5'))
                 + item(15, ('AddressOnParent', '1'), ('HostResource', 'ovf:/file/file1'), ('Parent', '3'),
                        ('VirtualQuantity', '1')))
        self.assertEqual(2, parse(items=items).virtual_system.hardware[0].vcpus)

    def test_unused_properties_are_ignored(self):
        items = item(3, ('Address', '0'), ('AutomaticAllocation', 'true'), ('Caption', 'CPU'),
                     ('Description', 'Number of CPUs'), ('Limit', '1000'), ('Reservation', '100'),
                     ('VirtualQuantity', '2'), ('Weight', '1000'))
        system = '<vssd:Caption>x</vssd:Caption><vssd:CreationTime>x</vssd:CreationTime>'
        parse(items=items, system=system)

    def test_non_standard_properties_are_refused(self):
        items = item(3, ('Unknown', 'x'), ('VirtualQuantity', '2'), ('cpu_per_socket', '1'))
        self.assertUnread(['Envelope/VirtualSystem/VirtualHardwareSection/Item/rasd:Unknown',
                           'Envelope/VirtualSystem/VirtualHardwareSection/Item/rasd:cpu_per_socket',
                           'Envelope/VirtualSystem/VirtualHardwareSection/System/vssd:Unknown'],
                          descriptor(items=items, system='<vssd:Unknown>x</vssd:Unknown>'))

    def test_standard_property_that_changes_the_guest_is_refused(self):
        items = (SCSI + item(17, ('Access', '1'), ('AddressOnParent', '0'), ('Parent', '3'), element='StorageItem'))
        self.assertUnread(['Envelope/VirtualSystem/VirtualHardwareSection/StorageItem/sasd:Access'],
                          descriptor(namespace=namespaces.OVF_2, items=items))

    def test_unused_properties_apply_only_to_their_own_class(self):
        caption = '<rasd:Caption>x</rasd:Caption>'
        self.assertUnread(['Envelope/VirtualSystem/VirtualHardwareSection/StorageItem/rasd:Caption',
                           'Envelope/VirtualSystem/VirtualHardwareSection/rasd:Caption'],
                          descriptor(namespace=namespaces.OVF_2,
                                     items=SCSI + item(17, ('AddressOnParent', '0'), ('Parent', '3'),
                                                       element='StorageItem', extra=caption) + caption))


class HardwareTestCase(DescriptorTestCase):
    def test_storage_controller_subtypes(self):
        for subtype, bus in (('AHCI', 'sata'), ('ahci', 'sata'), ('vmware.sata.ahci', 'sata'),
                             ('vmware.nvme.controller', 'nvme')):
            items = item(20, ('InstanceID', '3'), ('ResourceSubType', subtype)) + DISK
            self.assertEqual([ovf.Controller(instance_id='3', bus=bus)],
                             parse(items=items).virtual_system.hardware[0].controllers, subtype)

    def test_other_storage_controller_subtypes_are_refused(self):
        items = item(20, ('InstanceID', '3'), ('ResourceSubType', 'vmware.nvdimm.controller'))
        self.assertRefused(
            ovf.UnsupportedHardwareError,
            'Envelope/VirtualSystem/VirtualHardwareSection/Item is a hardware item of resource type 20 with the '
            'subtype "vmware.nvdimm.controller"',
            descriptor(items=items))
        parse(items=CPU + item(20, ('ResourceSubType', 'vmware.nvdimm.controller'), ('Unknown', 'x'),
                               attributes=' ovf:required="false"'))

    def test_unknown_types_are_refused_unless_not_required(self):
        for resource_type in (1, 21, 32768):
            self.assertRefused(ovf.UnsupportedHardwareError, 'resource type %d,' % resource_type,
                               descriptor(items=CPU + item(resource_type)))
            parse(items=CPU + item(resource_type, attributes=' ovf:required="false"'))

    def test_types_left_to_the_defaults(self):
        items = ''.join(item(resource_type, ('InstanceID', str(resource_type)))
                        for resource_type in (14, 15, 16, 23, 24, 35))
        hardware = parse(items=items).virtual_system.hardware[0]
        self.assertEqual(ovf.VirtualHardware(system_type='vmx-13'), hardware)

    def test_memory_units(self):
        for properties, expected in (
                ((('VirtualQuantity', '2'), ('VirtualQuantityUnits', 'byte * 2^30'),
                  ('AllocationUnits', 'byte * 2^20')), 2 * 2 ** 30),
                ((('VirtualQuantity', '2'), ('AllocationUnits', 'MegaBytes')), 2 * 2 ** 20),
                ((('VirtualQuantity', '2'), ('AllocationUnits', 'byte')), 2),
                ((('VirtualQuantity', '2048'),), 2048)):
            self.assertEqual(expected, parse(items=item(4, *properties)).virtual_system.hardware[0].memory_bytes,
                             properties)

    def test_memory_unit_that_is_not_bytes(self):
        self.assertRefused(
            ovf.UnknownAllocationUnitError,
            'Envelope/VirtualSystem/VirtualHardwareSection/Item/rasd:AllocationUnits: Unknown allocation unit '
            '"hertz * 10^6"',
            descriptor(items=item(4, ('AllocationUnits', 'hertz * 10^6'), ('VirtualQuantity', '1'))))

    def test_cpu_units_are_not_bytes_and_not_parsed(self):
        items = item(3, ('AllocationUnits', 'MegaHertz'), ('VirtualQuantity', '2'), ('VirtualQuantityUnits', '1'))
        self.assertEqual(2, parse(items=items).virtual_system.hardware[0].vcpus)

    def test_disk_capacity_units(self):
        for units, expected in ((None, 10), ('byte', 10), ('byte * 2^20', 10 * 2 ** 20),
                                ('GigaBytes', 10 * 2 ** 30)):
            attribute = '' if units is None else ' ovf:capacityAllocationUnits="%s"' % units
            disks = '<Disk ovf:diskId="vmdisk1" ovf:capacity="10"%s/>' % attribute
            self.assertEqual(expected, parse(disks=disks).disks[0].capacity_bytes, units)
        self.assertRefused(
            ovf.UnknownAllocationUnitError, 'Envelope/DiskSection/Disk@ovf:capacityAllocationUnits: Unknown',
            descriptor(disks='<Disk ovf:diskId="vmdisk1" ovf:capacity="10" ovf:capacityAllocationUnits="bytes"/>'))


class ConfigurationTestCase(DescriptorTestCase):
    def test_default_configuration(self):
        options = parse(envelope_sections=DEPLOYMENT_OPTIONS).deployment_options
        self.assertEqual(
            [ovf.DeploymentOption(id='small', default=False, label='Small', description='One CPU'),
             ovf.DeploymentOption(id='large', default=True, label='Large', description='Four CPUs'),
             ovf.DeploymentOption(id='huge', default=False, label='Huge', description='Eight CPUs')],
            options)

    def test_first_configuration_is_the_default_when_none_is_marked(self):
        sections = DEPLOYMENT_OPTIONS.replace(' ovf:default="true"', '')
        options = parse(envelope_sections=sections).deployment_options
        self.assertEqual([True, False, False], [option.default for option in options])

    def test_items_networks_and_properties_follow_the_default(self):
        items = (item(3, ('VirtualQuantity', '1'), ('Unknown', 'not read'), attributes=' ovf:configuration="small"')
                 + item(3, ('VirtualQuantity', '4'), attributes=' ovf:configuration="large huge"')
                 + MEMORY + SCSI + DISK + NIC)
        networks = ('<Network ovf:name="net"/><Network ovf:name="small-only" ovf:configuration="small"/>'
                    '<Network ovf:name="large-only" ovf:configuration="large"/>')
        product = '''<ProductSection>
      <Property ovf:key="a" ovf:type="string" ovf:configuration="small"><Unknown/></Property>
      <Property ovf:key="b" ovf:type="string" ovf:value="default">
        <Value ovf:configuration="small" ovf:value="small"/>
        <Value configuration="large" value="large"/>
      </Property>
      <Property ovf:key="c" ovf:type="string" ovf:value="default">
        <Value ovf:configuration="huge" ovf:value="huge"/>
      </Property>
    </ProductSection>'''
        envelope = parse(envelope_sections=DEPLOYMENT_OPTIONS, items=items, networks=networks,
                         system_sections=product)
        self.assertEqual(4, envelope.virtual_system.hardware[0].vcpus)
        self.assertEqual(['net', 'large-only'], [network.name for network in envelope.networks])
        self.assertEqual([('b', 'large'), ('c', 'default')],
                         [(p.key, p.value) for p in envelope.virtual_system.products[0].properties])

    def test_configuration_naming_no_configuration_is_refused(self):
        items = CPU + item(3, ('VirtualQuantity', '4'), attributes=' ovf:configuration="large medium"')
        self.assertRefused(
            ovf.BrokenReferenceError,
            'Item[2]@ovf:configuration names the configuration "medium", which DeploymentOptionSection does not hold',
            descriptor(envelope_sections=DEPLOYMENT_OPTIONS, items=items))
        self.assertRefused(ovf.BrokenReferenceError, 'names the configuration "large"',
                           descriptor(items=CPU + item(3, ('VirtualQuantity', '4'),
                                                       attributes=' ovf:configuration="large"')))

    def test_value_needs_a_configuration(self):
        product = ('<ProductSection><Property ovf:key="b" ovf:type="string"><Value ovf:value="x"/></Property>'
                   '</ProductSection>')
        self.assertRefused(ovf.MissingContentError, 'Property/Value has no ovf:configuration',
                           descriptor(envelope_sections=DEPLOYMENT_OPTIONS, system_sections=product))


class BoundTestCase(DescriptorTestCase):
    def test_ranges_are_passed_over(self):
        items = (item(4, ('InstanceID', '2'), ('Reservation', '512'), ('Unknown', 'x'), attributes=' ovf:bound="min"')
                 + item(4, ('InstanceID', '2'), ('VirtualQuantity', '1024'), ('AllocationUnits', 'byte * 2^20'))
                 + item(4, ('InstanceID', '2'), ('Reservation', '4096'), attributes=' ovf:bound="max"'))
        self.assertEqual(2 ** 30, parse(items=CPU + items).virtual_system.hardware[0].memory_bytes)

    def test_normal_is_read(self):
        items = item(3, ('VirtualQuantity', '6'), attributes=' ovf:bound="normal"')
        self.assertEqual(6, parse(items=items).virtual_system.hardware[0].vcpus)

    def test_other_bounds_are_refused(self):
        self.assertRefused(
            ovf.InvalidValueError, 'Item@ovf:bound is "middle", which is not min, normal or max',
            descriptor(items=item(3, ('VirtualQuantity', '6'), attributes=' ovf:bound="middle"')))


class PropertyReferenceTestCase(DescriptorTestCase):
    def _capacity(self, product, capacity='${size}', **parts):
        disks = ('<Disk ovf:diskId="vmdisk1" ovf:capacity="%s" ovf:capacityAllocationUnits="byte * 2^30"/>'
                 % capacity)
        return parse(disks=disks, system_sections=product, **parts).disks[0].capacity_bytes

    def test_resolved(self):
        product = '<ProductSection><Property ovf:key="size" ovf:type="int" ovf:value="5"/></ProductSection>'
        self.assertEqual(5 * 2 ** 30, self._capacity(product))

    def test_resolved_by_full_key_and_by_key_alone(self):
        product = ('<ProductSection ovf:class="app" ovf:instance="1">'
                   '<Property ovf:key="size" ovf:type="int" ovf:value="5"/></ProductSection>')
        self.assertEqual(5 * 2 ** 30, self._capacity(product, '${app.size.1}'))
        self.assertEqual(5 * 2 ** 30, self._capacity(product, '${size}'))

    def test_resolved_in_the_default_configuration(self):
        product = ('<ProductSection><Property ovf:key="size" ovf:type="int" ovf:value="5">'
                   '<Value ovf:configuration="large" ovf:value="50"/></Property></ProductSection>')
        self.assertEqual(50 * 2 ** 30, self._capacity(product, envelope_sections=DEPLOYMENT_OPTIONS))

    def test_unresolved(self):
        for product, fragment in (
                ('', 'refers to the property "size", which no ProductSection of the VirtualSystem holds'),
                ('<ProductSection><Property ovf:key="size" ovf:type="int"/></ProductSection>',
                 'refers to the property "size", which has no value in the default configuration'),
                ('<ProductSection><Property ovf:key="size" ovf:type="int" ovf:value="big"/></ProductSection>',
                 'Envelope/DiskSection/Disk@ovf:capacity, through the property "size", is "big"'),
                ('<ProductSection><Property ovf:key="size" ovf:type="int" ovf:value="5" ovf:configuration="small"/>'
                 '</ProductSection>',
                 'refers to the property "size", which applies only to configurations other than the default')):
            disks = '<Disk ovf:diskId="vmdisk1" ovf:capacity="${size}"/>'
            self.assertRefused(ovf.InvalidValueError, fragment,
                               descriptor(disks=disks, system_sections=product, envelope_sections=DEPLOYMENT_OPTIONS))


class BrokenReferenceTestCase(DescriptorTestCase):
    def test_disk_host_resource(self):
        items = SCSI + item(17, ('AddressOnParent', '0'), ('HostResource', 'ovf:/disk/vmdisk2'), ('Parent', '3'))
        self.assertRefused(
            ovf.BrokenReferenceError,
            'Envelope/VirtualSystem/VirtualHardwareSection/Item[2]/rasd:HostResource names the disk "vmdisk2", '
            'which the descriptor does not hold',
            descriptor(items=items))

    def test_file_host_resource(self):
        items = SCSI + item(15, ('HostResource', 'ovf:/file/file2'), ('Parent', '3'))
        self.assertRefused(ovf.BrokenReferenceError, 'names the file "file2"', descriptor(items=items))
        parse(items=SCSI + item(15, ('HostResource', 'ovf:/file/file1'), ('Parent', '3')))

    def test_other_host_resources_are_not_checked(self):
        for host_resource in ('', '/disk/vmdisk2', 'ovf:disk/vmdisk2', '/dev/cdrom', 'http://example.com/x'):
            items = SCSI + item(17, ('AddressOnParent', '0'), ('HostResource', host_resource), ('Parent', '3'))
            drive = parse(items=items).virtual_system.hardware[0].disk_drives[0]
            self.assertEqual(host_resource or None, drive.host_resource)

    def test_parent(self):
        items = SCSI + item(17, ('AddressOnParent', '0'), ('Parent', '9'))
        self.assertRefused(
            ovf.BrokenReferenceError,
            'Envelope/VirtualSystem/VirtualHardwareSection/Item[2]/rasd:Parent names the controller "9", which the '
            'VirtualHardwareSection does not hold',
            descriptor(items=items))

    def test_parent_after_the_drive(self):
        parse(items=DISK + SCSI)

    def test_file_ref(self):
        self.assertRefused(
            ovf.BrokenReferenceError,
            'Envelope/DiskSection/Disk@ovf:fileRef names the file "file2", which References does not hold',
            descriptor(disks='<Disk ovf:diskId="vmdisk1" ovf:fileRef="file2" ovf:capacity="1"/>'))


class SectionsTestCase(DescriptorTestCase):
    def test_product_eula_and_operating_system(self):
        sections = '''
    <Name>Example</Name>
    <ProductSection ovf:class="com.example" ovf:instance="1">
      <Info>x</Info>
      <Product>Appliance</Product>
      <Vendor>Example</Vendor>
      <Version>1.0</Version>
      <FullVersion>1.0.0</FullVersion>
      <ProductUrl>https://example.com/a</ProductUrl>
      <VendorUrl>https://example.com/</VendorUrl>
      <AppUrl>https://localhost/</AppUrl>
      <Icon ovf:fileId="file1" ovf:height="32" ovf:width="32" ovf:mimeType="image/png"/>
      <Property ovf:key="first" ovf:type="string" ovf:userConfigurable="true"/>
      <Category>Network</Category>
      <Property ovf:key="secret" ovf:type="string" ovf:password="true" ovf:qualifiers="MinLen(8)" ovf:value=""
                ovf:runtimeConfigurable="false">
        <Label>Secret</Label>
        <Description>A secret</Description>
      </Property>
      <Property ovf:key="other" ovf:type="string" ovf:isPassword="1"/>
    </ProductSection>
    <EulaSection><Info>x</Info><License>Terms</License></EulaSection>
    <EulaSection><Info>x</Info><License>More terms</License></EulaSection>
    <OperatingSystemSection ovf:id="94" ovf:version="22" vmw:osType="ubuntu64Guest">
      <Info>x</Info>
      <Description>Ubuntu</Description>
    </OperatingSystemSection>'''
        system = parse(system_sections=sections).virtual_system
        self.assertEqual('Example', system.name)
        self.assertEqual(
            [ovf.Product(
                product_class='com.example', instance='1', product='Appliance', vendor='Example', version='1.0',
                full_version='1.0.0', product_url='https://example.com/a', vendor_url='https://example.com/',
                app_url='https://localhost/',
                properties=[
                    ovf.Property(key='first', type='string', user_configurable=True, password=False),
                    ovf.Property(key='secret', type='string', user_configurable=False, password=True, value='',
                                 qualifiers='MinLen(8)', category='Network', label='Secret',
                                 description='A secret'),
                    ovf.Property(key='other', type='string', user_configurable=False, password=True,
                                 category='Network')])],
            system.products)
        self.assertEqual([ovf.Eula(license='Terms'), ovf.Eula(license='More terms')], system.eulas)
        self.assertEqual(ovf.OperatingSystem(id=94, version='22', os_type='ubuntu64Guest', description='Ubuntu'),
                         system.operating_system)

    def test_ovf_2_os_type_is_preferred(self):
        section = ('<OperatingSystemSection ovf:id="94" ovf:osType="ubuntu" vmw:osType="ubuntu64Guest">'
                   '<Info>x</Info></OperatingSystemSection>')
        self.assertEqual('ubuntu', parse(system_sections=section).virtual_system.operating_system.os_type)

    def test_property_booleans(self):
        for attribute in ('ovf:userConfigurable', 'ovf:password', 'ovf:isPassword', 'ovf:runtimeConfigurable'):
            product = ('<ProductSection><Property ovf:key="k" ovf:type="string" %s="yes"/></ProductSection>'
                       % attribute)
            self.assertRefused(ovf.InvalidValueError, '@%s is "yes", which is neither true nor false' % attribute,
                               descriptor(system_sections=product))

    def test_property_needs_a_key_and_a_type(self):
        for attributes, missing in (('ovf:type="string"', 'ovf:key'), ('ovf:key="k"', 'ovf:type')):
            product = '<ProductSection><Property %s/></ProductSection>' % attributes
            self.assertRefused(ovf.MissingContentError, 'Property has no %s' % missing,
                               descriptor(system_sections=product))

    def test_licence_must_have_text(self):
        self.assertRefused(ovf.MissingContentError, 'EulaSection has no License',
                           descriptor(system_sections='<EulaSection><Info>x</Info></EulaSection>'))
        self.assertRefused(ovf.MissingContentError, 'EulaSection/License is empty',
                           descriptor(system_sections='<EulaSection><Info>x</Info><License/></EulaSection>'))
        self.assertRefused(
            ovf.MissingContentError, 'its text is only in Strings, under the ovf:msgid "eula"',
            descriptor(system_sections='<EulaSection><Info>x</Info><License ovf:msgid="eula"/></EulaSection>'))

    def test_operating_system_id_must_be_an_integer(self):
        section = '<OperatingSystemSection ovf:id="-100"><Info>x</Info></OperatingSystemSection>'
        self.assertRefused(ovf.InvalidValueError, 'OperatingSystemSection@ovf:id is "-100"',
                           descriptor(system_sections=section))


class OvirtTestCase(DescriptorTestCase):
    def _oracle(self):
        with open(os.path.join(FIXTURES, 'vendor', 'oracle-linux-9.8-olvm.ovf'), 'rb') as f:
            return f.read()

    def test_ovirt_export_is_refused_by_name(self):
        self.assertRefused(ovf.UnsupportedProducerError, 'oVirt export', self._oracle())

    def test_declaration_anywhere_is_detected(self):
        parts = {'system_sections': '<ext:Section xmlns:ovirt="%s" ovf:required="false"/>' % namespaces.OVIRT}
        self.assertRefused(ovf.UnsupportedProducerError, 'oVirt export', descriptor(**parts))

    def test_without_the_declaration_an_ovirt_element_is_refused_instead(self):
        # Removing the declaration leaves ovirt:id unbound, which is not XML,
        # so that attribute goes too.
        data = self._oracle()
        stripped = data.replace(b' xmlns:ovirt="http://www.ovirt.org/ovf"', b'').replace(b' ovirt:id="5007"', b'')
        self.assertNotEqual(data, stripped)
        self.assertNotIn(namespaces.OVIRT.encode('utf-8'), stripped)
        # The first oVirt element the parser reaches is oVirt's video device.
        self.assertRefused(
            ovf.UnsupportedHardwareError,
            'Envelope/VirtualSystem/VirtualHardwareSection/Item[4] is a hardware item of resource type 32768',
            stripped)

        # Without that, and the disk drive whose Parent names no controller,
        # oVirt's other elements are refused as content the parser does not
        # understand.
        for caption in (b'Graphical Controller', b'Drive: 1'):
            stripped = re.sub(rb'<Item>\s*<rasd:Caption>' + caption + rb'.*?</Item>', b'', stripped, flags=re.S)
        e = self.assertRefused(ovf.UnparsedContentError, 'does not understand', stripped)
        for path in ('Envelope/DiskSection/Disk@ovf:boot', 'Envelope/DiskSection/Disk@ovf:disk-interface',
                     'Envelope/VirtualSystem/ClusterCompatibilityVersion'):
            self.assertIn('\n    %s\n' % path, str(e))
