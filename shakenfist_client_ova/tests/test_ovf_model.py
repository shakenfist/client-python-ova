import dataclasses
import json
import typing

import testtools

from shakenfist_client_ova import ovf
from shakenfist_client_ova.ovf import prose


def _envelope():
    return ovf.Envelope(
        namespace='http://schemas.dmtf.org/ovf/envelope/1',
        version='1.0',
        files=[ovf.File(id='file2', href='b.vmdk'), ovf.File(id='file1', href='a.vmdk', size=10)],
        disks=[ovf.Disk(disk_id='vmdisk1', file_ref='file1', capacity_bytes=1024 ** 3, format='vmdk')],
        networks=[ovf.Network(name='Netzwerkbrücke', description='虚拟机')],
        virtual_system=ovf.VirtualSystem(
            id='vm',
            hardware=[ovf.VirtualHardware(
                vcpus=2, memory_bytes=1024 ** 3,
                controllers=[ovf.Controller(instance_id='3', bus='scsi'), ovf.Controller(instance_id='1', bus='ide')],
                disk_drives=[ovf.DiskDrive(parent='3', address_on_parent=0, element_name='disk1')],
                nics=[ovf.Nic(resource_subtype='E1000', connection='NAT')])]))


class ToJsonTestCase(testtools.TestCase):
    def setUp(self):
        super(ToJsonTestCase, self).setUp()
        self.text = ovf.to_json(_envelope())

    def test_deterministic(self):
        self.assertEqual(self.text, ovf.to_json(_envelope()))

    def test_final_newline(self):
        self.assertTrue(self.text.endswith('}\n'))
        self.assertFalse(self.text.endswith('\n\n'))

    def test_sorted_keys(self):
        # Envelope declares namespace and virtual_system first, but sorting
        # puts them after the fields declared later.
        keys = [line.split('"')[1] for line in self.text.splitlines() if line.startswith('  "')]
        self.assertEqual(sorted(keys), keys)
        self.assertEqual(
            ['deployment_options', 'disks', 'files', 'namespace', 'networks', 'version', 'virtual_system'], keys)
        self.assertEqual(self.text, json.dumps(json.loads(self.text), sort_keys=True, indent=2,
                                               ensure_ascii=False) + '\n')

    def test_lists_keep_insertion_order(self):
        parsed = json.loads(self.text)
        self.assertEqual(['file2', 'file1'], [f['id'] for f in parsed['files']])
        controllers = parsed['virtual_system']['hardware'][0]['controllers']
        self.assertEqual(['3', '1'], [c['instance_id'] for c in controllers])

    def test_non_ascii_kept(self):
        self.assertIn('"Netzwerkbrücke"', self.text)
        self.assertIn('"虚拟机"', self.text)
        self.assertNotIn('\\u', self.text)

    def test_empty_fields_serialised(self):
        # Fields the parser does not read yet are present now, as null or an empty list.
        parsed = json.loads(self.text)
        self.assertIsNone(parsed['files'][0]['size'])
        self.assertEqual([], parsed['deployment_options'])
        self.assertIsNone(parsed['virtual_system']['operating_system'])

    def test_manifest(self):
        manifest = ovf.Manifest(entries=[
            ovf.ManifestEntry(name='a.vmdk', algorithm='sha256', digest='00'),
            ovf.ManifestEntry(name='a.vmdk', algorithm='sha1', digest='11')])
        self.assertEqual(
            {'entries': [{'algorithm': 'sha256', 'digest': '00', 'name': 'a.vmdk'},
                         {'algorithm': 'sha1', 'digest': '11', 'name': 'a.vmdk'}]},
            json.loads(ovf.to_json(manifest)))


class OutcomeNameTestCase(testtools.TestCase):
    def test_every_error_is_an_ovf_error(self):
        for cls in (ovf.ManifestError, ovf.UnknownAllocationUnitError, ovf.UnsupportedHardwareError,
                    ovf.UnparsedContentError, ovf.MalformedDescriptorError, ovf.EntityDeclarationError,
                    ovf.UnsupportedDescriptorError):
            self.assertTrue(issubclass(cls, ovf.OVFError), cls)

    def test_no_cause(self):
        self.assertEqual('UnparsedContentError', ovf.outcome_name(ovf.UnparsedContentError('left over')))

    def test_raised_from_key_error(self):
        def raiser():
            try:
                {}['v1:References']
            except KeyError as e:
                raise ovf.UnsupportedDescriptorError('Could not parse the descriptor') from e

        e = self.assertRaises(ovf.OVFError, raiser)
        self.assertEqual('UnsupportedDescriptorError(KeyError)', ovf.outcome_name(e))

    def test_raised_from_ovf_error(self):
        def raiser():
            try:
                raise ovf.UnknownAllocationUnitError('Unknown allocation unit: "byte"')
            except ovf.OVFError as e:
                raise ovf.UnsupportedHardwareError('Unknown hardware element') from e

        e = self.assertRaises(ovf.OVFError, raiser)
        self.assertEqual('UnsupportedHardwareError', ovf.outcome_name(e))

    def test_context_without_cause_ignored(self):
        # Only an explicit "raise ... from" names a cause.
        def raiser():
            try:
                {}['v1:References']
            except KeyError:
                raise ovf.MalformedDescriptorError('not well-formed')

        e = self.assertRaises(ovf.OVFError, raiser)
        self.assertEqual('MalformedDescriptorError', ovf.outcome_name(e))


def _populated_virtual_system():
    """A VirtualSystem with every string field filled, prose or not."""
    def prop(n):
        return ovf.Property(
            key='key%d' % n, type='string', user_configurable=True, password=False, value='value',
            qualifiers='MaxLen(64)', category='category%d' % n, label='label%d' % n, description='description%d' % n)

    def product(n):
        return ovf.Product(
            product_class='class', instance='instance', product='product%d' % n, vendor='vendor%d' % n,
            version='1.0', full_version='full_version%d' % n, product_url='product_url%d' % n,
            vendor_url='vendor_url%d' % n, app_url='app_url%d' % n, properties=[prop(1), prop(2)])

    return ovf.VirtualSystem(
        id='vm', name='name', description='description',
        hardware=[ovf.VirtualHardware(vcpus=1, system_type='vmx-13')],
        products=[product(1), product(2)],
        eulas=[ovf.Eula(license='license1'), ovf.Eula(license='license2')],
        operating_system=ovf.OperatingSystem(id=94, version='22.04', os_type='ubuntu64Guest',
                                             description='Ubuntu'))


class ScrubTestCase(testtools.TestCase):
    def test_every_prose_field_replaced(self):
        system = _populated_virtual_system()
        prose.scrub(system)
        trimmed = prose.PLACEHOLDER
        self.assertEqual(trimmed, system.description)
        self.assertEqual([trimmed, trimmed], [e.license for e in system.eulas])
        for product in system.products:
            for name in ('product', 'vendor', 'full_version', 'product_url', 'vendor_url', 'app_url'):
                self.assertEqual(trimmed, getattr(product, name), name)
            for p in product.properties:
                self.assertEqual((trimmed, trimmed, trimmed), (p.category, p.label, p.description))

    def test_other_fields_untouched(self):
        system = _populated_virtual_system()
        prose.scrub(system)
        self.assertEqual(('vm', 'name'), (system.id, system.name))
        self.assertEqual('vmx-13', system.hardware[0].system_type)
        self.assertEqual('Ubuntu', system.operating_system.description)
        for product in system.products:
            self.assertEqual(('class', 'instance', '1.0'), (product.product_class, product.instance, product.version))
            for p in product.properties:
                self.assertEqual(('string', 'value', 'MaxLen(64)'), (p.type, p.value, p.qualifiers))
            self.assertEqual(['key1', 'key2'], [p.key for p in product.properties])

    def test_none_and_empty_left_alone(self):
        system = ovf.VirtualSystem(
            description='',
            products=[ovf.Product(vendor='', properties=[
                ovf.Property(key='k', type='string', user_configurable=False, password=False, label='')])],
            eulas=[ovf.Eula(license='')])
        before = ovf.to_json(system)
        prose.scrub(system)
        self.assertEqual(before, ovf.to_json(system))
        self.assertIsNone(system.products[0].product)
        self.assertEqual('', system.products[0].vendor)

    def test_scrubbed_model_has_no_prose(self):
        system = _populated_virtual_system()
        prose.scrub(system)
        text = ovf.to_json(system)
        for prefix in ('description1', 'label1', 'category1', 'product1', 'vendor1', 'license1', 'app_url1'):
            self.assertNotIn(prefix, text)


def _unwrap_optional(tp):
    if getattr(tp, '__origin__', None) is typing.Union:
        args = [a for a in tp.__args__ if a is not type(None)]
        if len(args) == 1:
            return args[0]
    return tp


class ProseElementsTestCase(testtools.TestCase):
    def _resolve(self, path):
        """Walk a PROSE_ELEMENTS model path from VirtualSystem, returning the leaf's type."""
        tp = ovf.VirtualSystem
        for segment in path.split('.'):
            self.assertTrue(dataclasses.is_dataclass(tp), '%s: %s is not a dataclass' % (path, tp))
            name = segment[:-2] if segment.endswith('[]') else segment
            hints = typing.get_type_hints(tp)
            self.assertIn(name, [f.name for f in dataclasses.fields(tp)],
                          '%s: %s has no field %s' % (path, tp.__name__, name))
            tp = _unwrap_optional(hints[name])
            if segment.endswith('[]'):
                self.assertIs(list, getattr(tp, '__origin__', None), '%s: %s is not a list' % (path, segment))
                tp = tp.__args__[0]
            else:
                self.assertIsNot(list, getattr(tp, '__origin__', None),
                                 '%s: %s is a list, so needs []' % (path, segment))
        return tp

    def test_every_model_path_is_a_string_field(self):
        paths = [f for _, f in prose.PROSE_ELEMENTS if f]
        self.assertNotEqual([], paths)
        for path in paths:
            self.assertIs(str, self._resolve(path), path)

    def test_resolver_catches_a_typo(self):
        self.assertRaises(AssertionError, self._resolve, 'products[].vendr')
        self.assertRaises(AssertionError, self._resolve, 'products.vendor')
        self.assertRaises(AssertionError, self._resolve, 'eula[].license')

    def test_element_paths(self):
        # The trim tool matches on these, so they must keep their shape.
        for element, _ in prose.PROSE_ELEMENTS:
            self.assertRegex(element, r'^[A-Za-z]+(/[A-Za-z]+)+$')
        self.assertEqual(15, len(prose.PROSE_ELEMENTS))

    def test_placeholder(self):
        self.assertEqual('TRIMMED', prose.PLACEHOLDER)
