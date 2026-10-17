"""The descriptor parser.

A descriptor is read with defusedxml's ElementTree, which refuses entity
declarations and external references, into the dataclasses in model.py. OVF
1.x and 2.x are read the same way: every element and attribute name is mapped
through one table of namespaces, so the section readers below never see a
namespace URI, a prefix, or a producer's spelling of either.

The parser is strict, as DSP0243 asks of a consumer. It records every element
and attribute it reads, and when it has built the model it walks the whole
tree. Anything left unread is either ignored by one of the rules in
_ignored_element and _ignored_attribute, or refused with UnparsedContentError,
which names each unread thing by its path.
"""

import io
import re

import defusedxml
from defusedxml import ElementTree

from . import cim
from . import namespaces
from . import quirks
from . import units
from .errors import (
    BrokenReferenceError, EntityDeclarationError, InvalidValueError, MalformedDescriptorError, MissingContentError,
    UnknownAllocationUnitError, UnparsedContentError, UnsupportedEnvelopeError, UnsupportedHardwareError,
    UnsupportedProducerError, VirtualSystemCollectionError)
from .model import (
    Controller, DeploymentOption, Disk, DiskDrive, Envelope, Eula, File, Network, Nic, OperatingSystem, Product,
    Property, VirtualHardware, VirtualSystem)


# The name the parser reads each namespace under, keyed by URI. Both OVF
# envelope namespaces are read as one, and each producer alias in quirks.py as
# the namespace it means. A namespace that is not here is a custom one, read
# under its URI in braces.
OVF = 'ovf'
NAMESPACE_NAMES = {
    namespaces.OVF_1: OVF,
    namespaces.OVF_2: OVF,
    namespaces.RASD: 'rasd',
    namespaces.VSSD: 'vssd',
    namespaces.SASD: 'sasd',
    namespaces.EPASD: 'epasd',
    namespaces.VMWARE: 'vmw',
    namespaces.XML: 'xml',
    namespaces.XSI: 'xsi',
}
NAMESPACE_NAMES.update({alias: NAMESPACE_NAMES[uri] for alias, uri in quirks.NAMESPACE_ALIASES.items()})

# The CIM class namespaces, by the name the parser reads each under.
_CIM_NAMESPACES = frozenset(NAMESPACE_NAMES[uri] for uri in cim.PROPERTIES)

# Element names read as another, keyed by (namespace name, local name).
_ELEMENT_ALIASES = {
    (NAMESPACE_NAMES[uri], local): canonical for (uri, local), canonical in quirks.ELEMENT_ALIASES.items()}

# The standard CIM properties the parser reads, and those it leaves unread, by
# namespace name. A read property is recorded as read on every item or System
# that carries it, whether or not that item's kind uses its value.
_CIM_READ = {
    NAMESPACE_NAMES[namespaces.RASD]: cim.RASD_READ,
    NAMESPACE_NAMES[namespaces.SASD]: cim.SASD_READ,
    NAMESPACE_NAMES[namespaces.EPASD]: cim.EPASD_READ,
    NAMESPACE_NAMES[namespaces.VSSD]: cim.VSSD_READ,
}
_CIM_UNUSED = {NAMESPACE_NAMES[uri]: names for uri, names in cim.UNUSED.items()}

# The hardware item elements, each with the CIM class its children are
# properties of. System's children are CIM_VirtualSystemSettingData's.
ITEMS = {'Item': 'rasd', 'StorageItem': 'sasd', 'EthernetPortItem': 'epasd'}
_CIM_PARENTS = {(OVF, local): cim_class for local, cim_class in ITEMS.items()}
_CIM_PARENTS[(OVF, 'System')] = 'vssd'

# OVF elements ignored unread wherever they are. Each holds text for a person,
# which nothing in Shaken Fist reads: Info describes its parent, an
# AnnotationSection is a free-form note, and Strings holds translations of the
# other text, which ovf:msgid attributes point into.
IGNORED_ELEMENTS = frozenset([(OVF, 'Info'), (OVF, 'AnnotationSection'), (OVF, 'Strings')])

# At most this many unread paths are listed when content is refused.
MAX_UNREAD_LISTED = 20

UNPARSED_HEADING = 'The descriptor has content the parser does not understand:'

# CIM resource types, from CIM_ResourceAllocationSettingData.
CPU = 3
MEMORY = 4
IDE_CONTROLLER = 5
SCSI_CONTROLLER = 6
ETHERNET_ADAPTER = 10
DISK_DRIVE = 17
OTHER_STORAGE_CONTROLLER = 20

# The controllers the parser reads, by resource type, and for "other storage
# controller" by subtype. A subtype is matched in any case: producers write
# both AHCI and ahci.
CONTROLLER_BUSES = {IDE_CONTROLLER: 'ide', SCSI_CONTROLLER: 'scsi'}
OTHER_STORAGE_BUSES = {
    'ahci': 'sata',
    'vmware.sata.ahci': 'sata',
    'vmware.nvme.controller': 'nvme',
}

# Resource types recognised and left to the instance's defaults: floppy, CD and
# DVD drives, USB controllers, graphics controllers and sound cards.
DEFAULTED_TYPES = frozenset([14, 15, 16, 23, 24, 35])

# Every resource type the parser reads or recognises, other than the controllers.
KNOWN_TYPES = frozenset([CPU, MEMORY, ETHERNET_ADAPTER, DISK_DRIVE]) | DEFAULTED_TYPES

# A HostResource naming a disk or a file in the descriptor. Any other
# HostResource names something on the deployment platform, and is not checked.
_HOST_RESOURCE_RE = re.compile(
    r'^(?:%s)/(disk|file)/(.*)$' % '|'.join(re.escape(prefix) for prefix in quirks.HOST_RESOURCE_PREFIXES))

# A disk capacity given as a reference to a ProductSection property.
_PROPERTY_REFERENCE_RE = re.compile(r'^\$\{(.*)\}$')

# An unsigned integer. The digits are limited, which bounds the arithmetic done
# on a descriptor's text; no real value comes near the limit.
_INTEGER_RE = re.compile(r'^[0-9]{1,30}$')

# xs:boolean's values.
_BOOLEANS = {'true': True, '1': True, 'false': False, '0': False}

# A Property's types, from DSP0243's table of property types, which are CIM
# datatypes. They are matched in any case: CIM's datatype names are, and
# DSP0243 2.x's table writes String and Boolean where 1.x's writes string and
# boolean.
PROPERTY_TYPES = frozenset([
    'uint8', 'sint8', 'uint16', 'sint16', 'uint32', 'sint32', 'uint64', 'sint64', 'string', 'boolean', 'real32',
    'real64'])


def _split_tag(tag):
    """A tag or attribute key as ElementTree spells it, split into (URI, local name)."""
    if tag.startswith('{'):
        uri, _, local = tag[1:].partition('}')
        return uri, local
    return '', tag


def _namespace(uri):
    """The name the parser reads a namespace URI under: its NAMESPACE_NAMES entry, or the URI in braces."""
    if not uri:
        return ''
    return NAMESPACE_NAMES.get(uri, '{%s}' % uri)


def _element_key(element):
    uri, local = _split_tag(element.tag)
    namespace = _namespace(uri)
    return namespace, _ELEMENT_ALIASES.get((namespace, local), local)


def _attribute_key(key):
    uri, local = _split_tag(key)
    return _namespace(uri), local


def _name(text, default_namespace):
    """A name as the section readers write it, such as 'DiskSection' or 'rasd:ResourceType', as a key."""
    namespace, colon, local = text.partition(':')
    if not colon:
        return default_namespace, text
    return namespace, local


def _required_false(element, key, path):
    """Whether an element carries ovf:required="false", or an unqualified required="false" on an OVF element.

    The value is an xs:boolean, and any other value is refused.
    """
    required_false = False
    for attribute, value in element.attrib.items():
        namespace, local = _attribute_key(attribute)
        if local == 'required' and (namespace == OVF or (not namespace and key[0] == OVF)):
            result = _BOOLEANS.get(value.strip())
            if result is None:
                raise InvalidValueError('%s@%s is "%s", which is neither true nor false' % (
                    path, 'ovf:required' if namespace else 'required', value))
            if result is False:
                required_false = True
    return required_false


def _unique(seen, value, where):
    """Record that where gives value, refusing it if an earlier element already gave the same value in seen."""
    first = seen.get(value)
    if first is not None:
        raise InvalidValueError('%s repeats "%s", already given by %s' % (where, value, first))
    seen[value] = where


class _Reader(object):
    """One descriptor's tree, and a record of every element and attribute read from it."""

    def __init__(self, prefixes):
        # The document's own prefix for each namespace URI, for naming custom
        # elements and attributes in messages.
        self.prefixes = prefixes
        self.read = set()
        self.read_whole = set()
        self.read_attributes = set()
        self._steps = {}

    def display(self, namespace, local, attribute=False):
        """How a name is written in a path: OVF elements bare, everything else with a prefix."""
        if not namespace or (namespace == OVF and not attribute):
            return local
        if namespace.startswith('{'):
            prefix = self.prefixes.get(namespace[1:-1])
            return '%s:%s' % (prefix, local) if prefix else namespace + local
        return '%s:%s' % (namespace, local)

    def steps(self, element):
        """Each child element as (child, key, step), the step naming it in a path, numbered if its name repeats."""
        steps = self._steps.get(id(element))
        if steps is None:
            children = [child for child in element if isinstance(child.tag, str)]
            keys = [_element_key(child) for child in children]
            counts = {}
            for key in keys:
                counts[key] = counts.get(key, 0) + 1
            seen = {}
            steps = []
            for child, key in zip(children, keys):
                step = self.display(*key)
                if counts[key] > 1:
                    seen[key] = seen.get(key, 0) + 1
                    step = '%s[%d]' % (step, seen[key])
                steps.append((child, key, step))
            self._steps[id(element)] = steps
        return steps


class _Node(object):
    """An element being read. Reading a child or an attribute through it records that it was read.

    Names are written as the section readers write them: an element's name is
    in the OVF namespace unless it has a prefix, as in 'rasd:ResourceType', and
    an attribute's always has one, as in 'ovf:capacity'. The prefixes are the
    names in NAMESPACE_NAMES, not the document's.
    """

    def __init__(self, reader, element, path):
        self.reader = reader
        self.element = element
        self.path = path
        self.key = _element_key(element)
        reader.read.add(id(element))

    def entries(self):
        """Each child element as (child, key, path)."""
        return [(child, key, '%s/%s' % (self.path, step)) for child, key, step in self.reader.steps(self.element)]

    def children(self, *names):
        """Every child with one of the names, in document order, each recorded as read."""
        wanted = [_name(name, OVF) for name in names]
        return [_Node(self.reader, child, path) for child, key, path in self.entries() if key in wanted]

    def child(self, name):
        """The first child with the name, recorded as read, or None. Any second one is left unread."""
        wanted = _name(name, OVF)
        for child, key, path in self.entries():
            if key == wanted:
                return _Node(self.reader, child, path)
        return None

    def required_child(self, name):
        node = self.child(name)
        if node is None:
            raise MissingContentError('%s has no %s' % (self.path, self.reader.display(*_name(name, OVF))))
        return node

    def text(self):
        """The element's text, stripped, or None if it has none."""
        text = (self.element.text or '').strip()
        return text or None

    def child_text(self, name):
        node = self.child(name)
        return None if node is None else node.text()

    def required_child_text(self, name):
        node = self.required_child(name)
        text = node.text()
        if text is None:
            raise MissingContentError('%s is empty' % node.path)
        return text

    def attribute(self, name):
        """An attribute's value, recorded as read, or None if it is absent.

        On an element in the OVF namespace, an unqualified attribute is read as
        the OVF attribute of the same local name. An element carrying both forms
        is refused, because the two could disagree.
        """
        wanted = _name(name, '')
        found = []
        for key in self.element.attrib:
            namespace, local = _attribute_key(key)
            if local == wanted[1] and (
                    namespace == wanted[0] or (not namespace and wanted[0] == OVF and self.key[0] == OVF)):
                found.append(key)
        if not found:
            return None
        for key in found:
            self.reader.read_attributes.add((id(self.element), key))
        if len(found) > 1:
            raise UnparsedContentError(
                '%s carries %s more than once, qualified and unqualified, and the two could disagree'
                % (self.path, self.reader.display(*wanted, attribute=True)))
        return self.element.attrib[found[0]]

    def required_attribute(self, name):
        value = self.attribute(name)
        if value is None:
            raise MissingContentError('%s has no %s' % (
                self.path, self.reader.display(*_name(name, ''), attribute=True)))
        return value

    def members(self):
        """The descriptor elements the node is read from: itself, or for a combined item each item combined."""
        return [self]

    def skip(self):
        """Record the element and its whole subtree as read, for content deliberately passed over."""
        self.reader.read_whole.add(id(self.element))

    def mark_children(self, namespace, names):
        """Record as read every child in the namespace whose local name is in names."""
        for child, key, _ in self.entries():
            if key[0] == namespace and key[1] in names:
                self.reader.read.add(id(child))

    def describe(self, name):
        """The path of one of the element's attributes ('@ovf:size') or children ('rasd:Parent'), for a message."""
        if name.startswith('@'):
            return '%s@%s' % (self.path, self.reader.display(*_name(name[1:], ''), attribute=True))
        return '%s/%s' % (self.path, self.reader.display(*_name(name, OVF)))


class _CombinedItem(_Node):
    """Hardware items sharing an InstanceID in one configuration, read as the one item DSP0243 combines them into.

    Each child is taken from the last item that has a child of its name, and
    the like-named children of the items before it are passed over, as DSP0243
    says. Attributes are read from the last item, and so is the path that
    messages name, but each child's path names the item it came from. The one
    exception is ovf:required, which is read from every item: see
    _item_required.
    """

    def __init__(self, items):
        last = items[-1]
        super(_CombinedItem, self).__init__(last.reader, last.element, last.path)
        self.items = items
        picked = {}
        for item in items:
            by_key = {}
            for entry in item.entries():
                by_key.setdefault(entry[1], []).append(entry)
            for key, entries in by_key.items():
                for overridden in picked.get(key, []):
                    self.reader.read_whole.add(id(overridden[0]))
                picked[key] = entries
        self._entries = [entry for entries in picked.values() for entry in entries]

    def entries(self):
        return self._entries

    def members(self):
        return self.items

    def skip(self):
        for item in self.items:
            item.skip()


def _integer(value, where):
    stripped = value.strip()
    if not _INTEGER_RE.match(stripped):
        raise InvalidValueError('%s is "%s", which is not a non-negative integer' % (where, value))
    return int(stripped)


def _integer_attribute(node, name, required=False):
    value = node.required_attribute(name) if required else node.attribute(name)
    if value is None:
        return None
    return _integer(value, node.describe('@' + name))


def _integer_text(node, name, required=False):
    text = node.required_child_text(name) if required else node.child_text(name)
    if text is None:
        return None
    return _integer(text, node.describe(name))


def _boolean_attribute(node, name, default):
    value = node.attribute(name)
    if value is None:
        return default
    result = _BOOLEANS.get(value.strip())
    if result is None:
        raise InvalidValueError('%s is "%s", which is neither true nor false' % (node.describe('@' + name), value))
    return result


def _disk_boot(node):
    """The producer's boot-disk mark (see quirks.DISK_BOOT_ATTRIBUTE): true or false in any case, or None if absent."""
    value = node.attribute(quirks.DISK_BOOT_ATTRIBUTE)
    if value is None:
        return None
    result = {'true': True, 'false': False}.get(value.strip().lower())
    if result is None:
        raise InvalidValueError('%s is "%s", which is neither true nor false' % (
            node.describe('@' + quirks.DISK_BOOT_ATTRIBUTE), value))
    return result


def _bytes_per_unit(text, where):
    try:
        return units.bytes_per_unit(text)
    except UnknownAllocationUnitError as e:
        raise UnknownAllocationUnitError('%s: %s' % (where, e)) from None


class _Configurations(object):
    """The DeploymentOptionSection's configurations, and the default one, which the parser builds."""

    def __init__(self, options):
        self.ids = [option.id for option in options]
        self.default = next((option.id for option in options if option.default), None)

    def selected(self, node, required=False):
        """The ids of the configurations an element applies to, by its ovf:configuration list, each once.

        An element without one applies to every configuration, unless required
        says it must have one. With no DeploymentOptionSection, that is the
        one configuration there is, given as None. A name in the list that is
        not a configuration's id is refused, because DSP0243 allows only those.
        """
        name = 'ovf:configuration'
        configuration = node.required_attribute(name) if required else node.attribute(name)
        if configuration is None:
            return list(self.ids) or [None]
        names = []
        for configuration_id in configuration.split():
            if configuration_id not in self.ids:
                raise BrokenReferenceError(
                    '%s names the configuration "%s", which DeploymentOptionSection does not hold'
                    % (node.describe('@' + name), configuration_id))
            if configuration_id not in names:
                names.append(configuration_id)
        return names

    def applies(self, node, required=False):
        """Whether an element applies to the default configuration, by its ovf:configuration list."""
        return self.default in self.selected(node, required=required)


_ENCODING_MESSAGE = 'The descriptor declares a character encoding the parser cannot read'
_MULTI_BYTE_ENCODING = 'multi-byte encodings are not supported'


def _read_tree(data):
    """Parse the descriptor's bytes, returning its root element and each namespace URI it declares, with a prefix."""
    prefixes = {}
    root = None
    try:
        for event, item in ElementTree.iterparse(
                io.BytesIO(data), events=('start', 'start-ns'), forbid_dtd=False, forbid_entities=True,
                forbid_external=True):
            if event == 'start-ns':
                prefix, uri = item
                prefixes.setdefault(uri, prefix)
            elif root is None:
                root = item
    except ElementTree.ParseError as e:
        position = getattr(e, 'position', None)
        where = ': the first error is at line %d, column %d' % position if position else ''
        raise MalformedDescriptorError('The descriptor is not well-formed XML%s' % where) from None
    except defusedxml.EntitiesForbidden as e:
        raise EntityDeclarationError(
            'The descriptor declares an entity, "%s", which the parser refuses: no OVF descriptor needs one'
            % e.name) from None
    except defusedxml.ExternalReferenceForbidden:
        raise EntityDeclarationError(
            'The descriptor refers to an external entity, which the parser refuses: no OVF descriptor needs one'
        ) from None
    except defusedxml.DTDForbidden:
        # Defensive: iterparse is called with forbid_dtd=False, so this is not
        # raised today. A DOCTYPE without entities is deliberately allowed, and
        # an entity declaration is refused through EntitiesForbidden above.
        raise EntityDeclarationError(
            'The descriptor declares a document type, which the parser refuses: no OVF descriptor needs one') from None
    except (LookupError, UnicodeError):
        # The XML parser decodes an encoding it does not know itself through
        # Python's codecs, which refuse an unknown one with a LookupError.
        raise MalformedDescriptorError(_ENCODING_MESSAGE) from None
    except ValueError as e:
        # expat refuses a multi-byte encoding other than UTF-16 with a plain
        # ValueError. Any other ValueError is not an encoding failure, and is
        # left to propagate. defusedxml's refusals are ValueErrors too, so
        # come first.
        if _MULTI_BYTE_ENCODING not in str(e):
            raise
        raise MalformedDescriptorError(_ENCODING_MESSAGE) from None
    return root, prefixes


def _check_envelope(root):
    """The envelope's namespace URI, or raise UnsupportedEnvelopeError."""
    uri, local = _split_tag(root.tag)
    if uri in namespaces.OVF_ENVELOPES and local == 'Envelope':
        return uri
    if uri == namespaces.OVF_0_9:
        raise UnsupportedEnvelopeError(
            'The descriptor is an OVF 0.9 envelope, in the namespace %s, and only OVF 1.x and 2.x envelopes are '
            'read' % uri)
    if not uri:
        where = 'in no namespace'
    elif uri in namespaces.OVF_ENVELOPES:
        where = 'in the OVF namespace %s, but is not Envelope' % uri
    else:
        where = 'in the namespace %s' % uri
    raise UnsupportedEnvelopeError(
        'The descriptor is not an OVF 1.x or 2.x envelope: its root element %s is %s' % (local, where))


def _read_files(envelope):
    files = []
    ids = {}
    for node in envelope.required_child('References').children('File'):
        file_id = node.required_attribute('ovf:id')
        _unique(ids, file_id, node.describe('@ovf:id'))
        files.append(File(
            id=file_id,
            href=node.required_attribute('ovf:href'),
            size=_integer_attribute(node, 'ovf:size'),
            compression=node.attribute('ovf:compression'),
            chunk_size=_integer_attribute(node, 'ovf:chunkSize')))
    return files


def _read_deployment_options(envelope):
    """Every configuration, with only the default one marked default."""
    section = envelope.child('DeploymentOptionSection')
    if section is None:
        return []

    options = []
    ids = {}
    for node in section.children('Configuration'):
        option_id = node.required_attribute('ovf:id')
        _unique(ids, option_id, node.describe('@ovf:id'))
        options.append(DeploymentOption(
            id=option_id,
            default=_boolean_attribute(node, 'ovf:default', False),
            label=node.child_text('Label'),
            description=node.child_text('Description')))
    if options:
        # The default is the first marked default, or else the first.
        chosen = next((option for option in options if option.default), options[0])
        for option in options:
            option.default = option is chosen
    return options


def _read_property(node, category, configurations):
    value = node.attribute('ovf:value')
    # A Value child gives the property's value in the configurations it names,
    # and no two may name the same one.
    configured_by = {}
    for value_node in node.children('Value'):
        configured = value_node.required_attribute('ovf:value')
        for configuration_id in configurations.selected(value_node, required=True):
            _unique(configured_by, configuration_id, value_node.describe('@ovf:configuration'))
        if configurations.applies(value_node, required=True):
            value = configured

    # Read for validity only: whether a property may change while the
    # appliance runs is the deployment tool's business.
    _boolean_attribute(node, 'ovf:runtimeConfigurable', False)
    # ovf:isPassword is OVF 2's name for ovf:password.
    password = _boolean_attribute(node, 'ovf:password', False)
    password = _boolean_attribute(node, 'ovf:isPassword', False) or password

    property_type = node.required_attribute('ovf:type')
    if property_type.strip().lower() not in PROPERTY_TYPES | quirks.PROPERTY_TYPES:
        raise InvalidValueError('%s is "%s", which is not a property type' % (
            node.describe('@ovf:type'), property_type))

    return Property(
        key=node.required_attribute('ovf:key'),
        type=property_type,
        user_configurable=_boolean_attribute(node, 'ovf:userConfigurable', False),
        password=password,
        value=value,
        qualifiers=node.attribute('ovf:qualifiers'),
        category=category,
        label=node.child_text('Label'),
        description=node.child_text('Description'))


def _full_key(product_class, key, instance):
    """A property's full key: class.key.instance, with the class and the instance only where they are given."""
    return '.'.join(part for part in (product_class, key, instance) if part)


def _read_product(node, configurations, excluded, full_keys):
    """Read a ProductSection, adding to excluded the keys of properties the default configuration leaves out.

    full_keys holds the full key of every property in the VirtualSystem's
    earlier ProductSections, with the path that gives it, and this section's
    are added. A ${key} reference is resolved by full key, so each must be
    unique across the VirtualSystem, as each key must be within its section.
    """
    product = Product(
        product_class=node.attribute('ovf:class'),
        instance=node.attribute('ovf:instance'),
        product=node.child_text('Product'),
        vendor=node.child_text('Vendor'),
        version=node.child_text('Version'),
        full_version=node.child_text('FullVersion'),
        product_url=node.child_text('ProductUrl'),
        vendor_url=node.child_text('VendorUrl'),
        app_url=node.child_text('AppUrl'))

    # An Icon is read for validity, and not modelled.
    for icon in node.children('Icon'):
        icon.required_attribute('ovf:fileId')
        _integer_attribute(icon, 'ovf:height')
        _integer_attribute(icon, 'ovf:width')
        icon.attribute('ovf:mimeType')

    # A Category heads the properties after it.
    category = None
    keys = {}
    for child in node.children('Category', 'Property'):
        if child.key[1] == 'Category':
            category = child.text()
            continue
        if configurations.applies(child):
            prop = _read_property(child, category, configurations)
            product.properties.append(prop)
            key = prop.key
        else:
            key = child.attribute('ovf:key')
            if key:
                excluded.update([key, _full_key(product.product_class, key, product.instance)])
            child.skip()
        if key:
            where = child.describe('@ovf:key')
            _unique(keys, key, where)
            full_key = _full_key(product.product_class, key, product.instance)
            if full_key in full_keys:
                raise InvalidValueError('%s gives the property the full key "%s", already given by %s' % (
                    where, full_key, full_keys[full_key]))
            full_keys[full_key] = where
    return product


def _property_values(products):
    """Each property's value in the default configuration, by its full key and by its key alone.

    DSP0243 2.x names the property a ${key} capacity refers to by its key alone,
    and 1.x's example reads as a full key. A full key is matched first, and
    otherwise the first property in document order with that key.
    """
    values = {}
    for product in products:
        for prop in product.properties:
            values.setdefault(prop.key, prop.value)
    for product in products:
        for prop in product.properties:
            values[_full_key(product.product_class, prop.key, product.instance)] = prop.value
    return values


def _license(section):
    node = section.required_child('License')
    text = node.text()
    if text is None:
        msgid = node.attribute('ovf:msgid')
        if msgid:
            raise MissingContentError(
                '%s is empty: its text is only in Strings, under the ovf:msgid "%s", and the parser does not read '
                'Strings' % (node.path, msgid))
        raise MissingContentError('%s is empty' % node.path)
    return text


def _read_operating_system(node):
    os_type = node.attribute('ovf:osType')
    # VMware writes the guest type as vmw:osType, which OVF 2 standardised as
    # ovf:osType. It is read by name, although custom attributes are not read.
    vmware_os_type = node.attribute('vmw:osType')
    return OperatingSystem(
        id=_integer_attribute(node, 'ovf:id', required=True),
        version=node.attribute('ovf:version'),
        os_type=os_type if os_type is not None else vmware_os_type,
        description=node.child_text('Description'))


def _capacity(node, property_values, excluded_properties):
    """A disk's ovf:capacity, resolving a ${key} reference to a ProductSection property."""
    capacity = node.required_attribute('ovf:capacity')
    where = node.describe('@ovf:capacity')
    reference = _PROPERTY_REFERENCE_RE.match(capacity.strip())
    if not reference:
        return _integer(capacity, where)

    key = reference.group(1)
    if key not in property_values:
        if key in excluded_properties:
            raise InvalidValueError(
                '%s refers to the property "%s", which applies only to configurations other than the default'
                % (where, key))
        raise InvalidValueError(
            '%s refers to the property "%s", which no ProductSection of the VirtualSystem holds' % (where, key))
    value = property_values[key]
    if value is None:
        raise InvalidValueError(
            '%s refers to the property "%s", which has no value in the default configuration' % (where, key))
    return _integer(value, '%s, through the property "%s",' % (where, key))


def _read_disks(envelope, files, property_values, excluded_properties):
    section = envelope.child('DiskSection')
    if section is None:
        return []

    file_ids = set(file.id for file in files)
    disk_ids = {}
    file_refs = {}
    nodes = section.children('Disk')
    disks = []
    for node in nodes:
        disk_id = node.required_attribute('ovf:diskId')
        _unique(disk_ids, disk_id, node.describe('@ovf:diskId'))
        capacity = _capacity(node, property_values, excluded_properties)
        unit = node.attribute('ovf:capacityAllocationUnits')
        factor = 1 if unit is None else _bytes_per_unit(unit, node.describe('@ovf:capacityAllocationUnits'))

        file_ref = node.attribute('ovf:fileRef')
        if file_ref is not None:
            if file_ref not in file_ids:
                raise BrokenReferenceError('%s names the file "%s", which References does not hold' % (
                    node.describe('@ovf:fileRef'), file_ref))
            # DSP0243: different Disk elements shall not name the same file.
            _unique(file_refs, file_ref, node.describe('@ovf:fileRef'))

        # DSP0243: the populated size may be an estimate, but is never larger
        # than the capacity.
        populated_size = _integer_attribute(node, 'ovf:populatedSize')
        if populated_size is not None and populated_size > capacity * factor:
            raise InvalidValueError('%s is %d bytes, more than the disk\'s capacity of %d bytes' % (
                node.describe('@ovf:populatedSize'), populated_size, capacity * factor))

        disks.append(Disk(
            disk_id=disk_id,
            capacity_bytes=capacity * factor,
            file_ref=file_ref,
            format=node.attribute('ovf:format'),
            populated_size=populated_size,
            parent_ref=node.attribute('ovf:parentRef'),
            boot=_disk_boot(node)))

    # A delta disk's parent is checked once every disk is known, so that the
    # parent may come after it.
    for node, disk in zip(nodes, disks):
        if disk.parent_ref is not None and disk.parent_ref not in disk_ids:
            raise BrokenReferenceError('%s names the disk "%s", which DiskSection does not hold' % (
                node.describe('@ovf:parentRef'), disk.parent_ref))
    return disks


def _read_networks(envelope, configurations):
    section = envelope.child('NetworkSection')
    if section is None:
        return []

    networks = []
    names = {}
    for node in section.children('Network'):
        # A name is unique within the envelope, whatever configurations its
        # networks apply to.
        name = node.required_attribute('ovf:name')
        _unique(names, name, node.describe('@ovf:name'))
        if configurations.applies(node):
            networks.append(Network(name=name, description=node.child_text('Description')))
        else:
            node.skip()
    return networks


def _host_resource(item, cim_class, disk_ids, file_ids):
    """Check each of an item's HostResources that names a disk or a file, and return the first one's text."""
    first = None
    for index, node in enumerate(item.children('%s:HostResource' % cim_class)):
        text = node.text()
        if index == 0:
            first = text
        match = _HOST_RESOURCE_RE.match(text or '')
        if match:
            kind, target = match.groups()
            if target not in (disk_ids if kind == 'disk' else file_ids):
                raise BrokenReferenceError('%s names the %s "%s", which the descriptor does not hold' % (
                    node.path, kind, target))
    return first


def _item_required(item):
    """Whether a hardware item is required: not if it says ovf:required="false", and for a combined item not unless
    every item combined says so, because a device that any of its items needs is needed."""
    return any(_boolean_attribute(member, 'ovf:required', True) for member in item.members())


def _read_item(item, instance_id, resource_type, hardware, drives, references, singletons):
    """Read a hardware item that applies into hardware, collecting a disk drive in drives with its item.

    references holds the ids of the descriptor's disks and files, and the
    names of the networks in the default configuration, by kind. singletons
    records the path of the item read for each resource type that a virtual
    system has only one of, the processor and the memory, so that a second is
    refused rather than silently replacing the first.
    """
    cim_class = ITEMS[item.key[1]]

    def name(local):
        return '%s:%s' % (cim_class, local)

    subtype = item.child_text(name('ResourceSubType'))
    required = _item_required(item)

    bus = CONTROLLER_BUSES.get(resource_type)
    if resource_type == OTHER_STORAGE_CONTROLLER:
        bus = OTHER_STORAGE_BUSES.get((subtype or '').lower())
    if bus is None and resource_type not in KNOWN_TYPES:
        if not required:
            item.skip()
            return
        kind = 'resource type %d' % resource_type
        if resource_type == OTHER_STORAGE_CONTROLLER:
            kind += ' with no ResourceSubType' if subtype is None else ' with the subtype "%s"' % subtype
        raise UnsupportedHardwareError(
            '%s is a hardware item of %s, which the parser does not support' % (item.path, kind))

    host_resource = _host_resource(item, cim_class, references['disk'], references['file'])

    if resource_type in (CPU, MEMORY):
        if resource_type in singletons:
            raise InvalidValueError('%s is a second %s item for the default configuration, after %s' % (
                item.path, 'processor' if resource_type == CPU else 'memory', singletons[resource_type]))
        singletons[resource_type] = item.path

    if resource_type == CPU:
        hardware.vcpus = _integer_text(item, name('VirtualQuantity'), required=True)
    elif resource_type == MEMORY:
        quantity = _integer_text(item, name('VirtualQuantity'), required=True)
        # VirtualQuantityUnits is the unit of VirtualQuantity. Producers wrote
        # AllocationUnits for it before CIM added VirtualQuantityUnits, and with
        # neither the quantity is in bytes.
        unit_name = name('VirtualQuantityUnits')
        unit = item.child_text(unit_name)
        if unit is None:
            unit_name = name('AllocationUnits')
            unit = item.child_text(unit_name)
        factor = 1 if unit is None else _bytes_per_unit(unit, item.describe(unit_name))
        hardware.memory_bytes = quantity * factor
    elif bus is not None:
        hardware.controllers.append(Controller(instance_id=instance_id, bus=bus))
    elif resource_type == ETHERNET_ADAPTER:
        # DSP0243: a Connection naming a network names one in the
        # NetworkSection.
        connection = item.child_text(name('Connection'))
        if connection is not None and connection not in references['network']:
            raise BrokenReferenceError('%s names the network "%s", which NetworkSection does not hold' % (
                item.describe(name('Connection')), connection))
        hardware.nics.append(Nic(resource_subtype=subtype, connection=connection))
    elif resource_type == DISK_DRIVE:
        drive = DiskDrive(
            parent=item.required_child_text(name('Parent')),
            address_on_parent=_integer_text(item, name('AddressOnParent'), required=True),
            element_name=item.child_text(name('ElementName')),
            host_resource=host_resource)
        hardware.disk_drives.append(drive)
        drives.append((item, drive))


def _check_instance_id(item, instance_id, resource_type, bound, configurations, seen):
    """Refuse an item whose InstanceID clashes with an earlier item's in its VirtualHardwareSection.

    DSP0243 lets several items share an InstanceID: normal items, to be
    combined into one, and the range markers of that one. seen records the
    resource type of each InstanceID given so far, under 'types', and the
    range marker giving each InstanceID in each configuration, under
    'markers', so that two of DSP0243's rules are checked:

    * Items sharing an InstanceID agree on their resource type.
    * A range has at most one ovf:bound="min" and one ovf:bound="max" range
      marker in any one configuration. A second would leave the range
      ambiguous.
    """
    first = seen['types'].get(instance_id)
    if first is None:
        seen['types'][instance_id] = (resource_type, item.path)
    elif first[0] != resource_type:
        raise InvalidValueError(
            '%s repeats the InstanceID "%s" of %s, but with the resource type %d rather than %d'
            % (item.path, instance_id, first[1], resource_type, first[0]))

    if bound == 'normal':
        return
    for configuration_id in configurations.selected(item):
        key = (configuration_id, bound, instance_id)
        first = seen['markers'].get(key)
        if first is None:
            seen['markers'][key] = item.path
            continue
        where = '' if configuration_id is None else ' in the configuration "%s"' % configuration_id
        raise InvalidValueError(
            '%s is a second ovf:bound="%s" range marker for the InstanceID "%s", after %s%s'
            % (item.path, bound, instance_id, first, where))


def _read_hardware(section, configurations, references):
    transport = section.attribute('ovf:transport')
    hardware = VirtualHardware(transport=transport.split() if transport else [])

    system = section.child('System')
    if system is not None:
        system.mark_children('vssd', _CIM_READ['vssd'])
        hardware.system_type = system.child_text('vssd:VirtualSystemType')
        hardware.system_identifier = system.child_text('vssd:VirtualSystemIdentifier')

    # The normal items of the default configuration, grouped by InstanceID in
    # the order each InstanceID first appears, each with its resource type.
    groups = {}
    instance_ids = {'types': {}, 'markers': {}}
    for item in section.children(*ITEMS):
        # Every item has an InstanceID and a resource type, whichever
        # configuration it applies to.
        cim_class = ITEMS[item.key[1]]
        item.mark_children(cim_class, _CIM_READ[cim_class])
        instance_id = item.required_child_text('%s:InstanceID' % cim_class)
        resource_type = _integer_text(item, '%s:ResourceType' % cim_class, required=True)
        bound = item.attribute('ovf:bound')
        if bound not in (None, 'normal', 'min', 'max'):
            raise InvalidValueError(
                '%s is "%s", which is not min, normal or max' % (item.describe('@ovf:bound'), bound))
        _check_instance_id(item, instance_id, resource_type, bound or 'normal', configurations, instance_ids)

        if not configurations.applies(item):
            item.skip()
            continue
        if bound in ('min', 'max'):
            # A range for a deployment tool to tune within. The parser reads
            # the normal value, which is the item without a bound.
            item.skip()
            continue
        groups.setdefault(instance_id, (resource_type, []))[1].append(item)

    # Normal items sharing an InstanceID are one device, as DSP0243 says, so
    # that a reference to that InstanceID names one thing.
    drives = []
    singletons = {}
    for instance_id, (resource_type, items) in groups.items():
        item = items[0] if len(items) == 1 else _CombinedItem(items)
        _read_item(item, instance_id, resource_type, hardware, drives, references, singletons)

    controller_ids = set(controller.instance_id for controller in hardware.controllers)
    for item, drive in drives:
        if drive.parent not in controller_ids:
            raise BrokenReferenceError(
                '%s names the controller "%s", which the VirtualHardwareSection does not hold'
                % (item.describe(ITEMS[item.key[1]] + ':Parent'), drive.parent))
    return hardware


def _ignored_element(key, parent_key):
    """Whether an unread element is ignored, with its whole subtree, rather than refused."""
    if key in IGNORED_ELEMENTS:
        return True
    # A standard property of the CIM class its parent item or System holds,
    # which the parser deliberately leaves unread (see cim.py).
    cim_class = _CIM_PARENTS.get(parent_key)
    return cim_class is not None and key[0] == cim_class and key[1] in _CIM_UNUSED[cim_class]


def _ignored_attribute(namespace, local, element_key):
    """Whether an unread attribute is ignored rather than refused."""
    if not namespace:
        # An unqualified attribute belongs to its element's namespace: on an
        # OVF element it is the OVF attribute of the same name.
        namespace = element_key[0]
    if namespace == OVF:
        # ovf:required is applied by the end-of-parse check itself, and
        # ovf:msgid only points into Strings.
        return local in ('required', 'msgid')
    # A custom attribute "shall not be required for correct behavior"
    # (DSP0243 section 7.3), so any attribute outside the OVF and CIM
    # namespaces is ignored. That covers xml:lang and xsi:schemaLocation.
    return namespace not in _CIM_NAMESPACES


# How much of what the end-of-parse check finds unread inside an element marked
# ovf:required="false" is ignored. Inside a hardware item or System so marked,
# everything is. Inside any other element so marked, such as a
# VirtualHardwareSection, everything is except a CIM property its class does
# not hold or the parser refuses, which is refused as it would be elsewhere.
_OPTIONAL_WHOLE = 'whole'
_OPTIONAL_INHERITED = 'inherited'


def _unread(reader, root):
    """The sorted path of every unread element and attribute no rule ignores, each unread subtree once, at its root."""
    found = []

    def walk(element, key, path, optional):
        # Anything inside an element marked ovf:required="false" is ignored
        # when it is not understood, as OVF permits, within the limits above.
        if _required_false(element, key, path):
            optional = _OPTIONAL_WHOLE if optional == _OPTIONAL_WHOLE or key in _CIM_PARENTS else _OPTIONAL_INHERITED
        for attribute in element.attrib:
            if optional or (id(element), attribute) in reader.read_attributes:
                continue
            namespace, local = _attribute_key(attribute)
            if not _ignored_attribute(namespace, local, key):
                found.append('%s@%s' % (path, reader.display(namespace, local, attribute=True)))
        for child, child_key, step in reader.steps(element):
            child_path = '%s/%s' % (path, step)
            if id(child) in reader.read_whole:
                continue
            if id(child) in reader.read:
                walk(child, child_key, child_path, optional)
                continue
            # An unread element marked ovf:required="false" itself is ignored
            # with its whole subtree, wherever it is.
            if _required_false(child, child_key, child_path) or _ignored_element(child_key, key):
                continue
            if optional == _OPTIONAL_WHOLE:
                continue
            if optional == _OPTIONAL_INHERITED and child_key[0] not in _CIM_NAMESPACES:
                continue
            found.append(child_path)

    walk(root, _element_key(root), 'Envelope', None)
    return sorted(found)


def _refuse_unread(reader, root):
    found = _unread(reader, root)
    if not found:
        return
    lines = [UNPARSED_HEADING] + ['    %s' % path for path in found[:MAX_UNREAD_LISTED]]
    if len(found) > MAX_UNREAD_LISTED:
        lines.append('    ... and %d more' % (len(found) - MAX_UNREAD_LISTED))
    raise UnparsedContentError('\n'.join(lines))


def parse_descriptor(data):
    """Parse a descriptor's bytes into an Envelope. Raises an OVFError subclass for every failure."""
    root, prefixes = _read_tree(data)
    envelope_namespace = _check_envelope(root)
    if quirks.OVIRT_NAMESPACE in prefixes:
        raise UnsupportedProducerError(
            'The descriptor is an oVirt export: it declares the oVirt namespace %s. oVirt writes its own dialect '
            'of OVF, which the parser does not read' % quirks.OVIRT_NAMESPACE)

    reader = _Reader(prefixes)
    envelope = _Node(reader, root, 'Envelope')
    if envelope.child('VirtualSystemCollection') is not None:
        raise VirtualSystemCollectionError(
            'The descriptor holds a VirtualSystemCollection, which describes several virtual machines, and only a '
            'single VirtualSystem can be imported')

    version = envelope.attribute('ovf:version')
    files = _read_files(envelope)
    deployment_options = _read_deployment_options(envelope)
    configurations = _Configurations(deployment_options)

    system_node = envelope.required_child('VirtualSystem')
    system = VirtualSystem(
        id=system_node.required_attribute('ovf:id'),
        name=system_node.child_text('Name'),
        description=system_node.child_text('Description'))
    excluded_properties = set()
    full_keys = {}
    products = {}
    for node in system_node.children('ProductSection'):
        # Each ProductSection has its own ovf:class and ovf:instance pair, each
        # defaulting to an empty string.
        pair = (node.attribute('ovf:class') or '', node.attribute('ovf:instance') or '')
        if pair in products:
            raise InvalidValueError(
                '%s repeats the ovf:class "%s" and ovf:instance "%s", already given by %s'
                % (node.path, pair[0], pair[1], products[pair]))
        products[pair] = node.path
        system.products.append(_read_product(node, configurations, excluded_properties, full_keys))
    for node in system_node.children('EulaSection'):
        system.eulas.append(Eula(license=_license(node)))
    operating_system = system_node.child('OperatingSystemSection')
    if operating_system is not None:
        system.operating_system = _read_operating_system(operating_system)

    disks = _read_disks(envelope, files, _property_values(system.products), excluded_properties)
    networks = _read_networks(envelope, configurations)

    references = {
        'disk': set(disk.disk_id for disk in disks),
        'file': set(file.id for file in files),
        'network': set(network.name for network in networks),
    }
    for node in system_node.children('VirtualHardwareSection'):
        system.hardware.append(_read_hardware(node, configurations, references))
    if not system.hardware:
        raise MissingContentError('%s has no VirtualHardwareSection' % system_node.path)

    _refuse_unread(reader, root)

    return Envelope(
        namespace=envelope_namespace,
        version=version,
        files=files,
        disks=disks,
        networks=networks,
        deployment_options=deployment_options,
        virtual_system=system)
