#!/usr/bin/env python3
"""Trim a vendor OVF descriptor so that it can be committed as a test fixture.

This repository is public, and vendor descriptors carry licence text, product
marketing and, in VirtualBox exports, the exporting host's configuration. This
tool replaces the content of each prose element with TRIMMED and empties each
element on an allow-list of ignored vendor elements, keeping only the
attributes the list allows.

It is a byte splicer, not a re-serialiser. A re-serialised descriptor is a
different descriptor: ElementTree keeps one prefix per namespace, drops prolog
comments, and forgets declarations used only inside attribute values, and each
of those is a shape the parser has to be tested against. So the original is
parsed (with defusedxml's protected expat parser) only to find byte offsets,
and the output is the original's bytes with three kinds of change: prose
content replaced, listed elements emptied, and one provenance comment inserted
after the XML declaration. Everything else is byte-for-byte the original's.

    trim-ovf-descriptor.py --source TEXT ORIGINAL OUTPUT
    trim-ovf-descriptor.py --check ORIGINAL TRIMMED

--check re-derives the spans in both files and fails, naming the first byte
offset and element where the rule is broken, unless the trimmed file differs
from the original only by those changes. The tool splices bytes and
never re-serialises, because a re-serialised descriptor is a different one:
it would lose prolog comments and the envelope's default namespace, which are
shapes the parser must be tested against. docs/development.md, "Test
fixtures", describes the rules.
"""

import argparse
import hashlib
import io
import re
import sys
import xml.sax
import xml.sax.handler
import xml.sax.xmlreader

from defusedxml import expatreader

from shakenfist_client_ova.ovf import prose
from shakenfist_client_ova.ovf.prose import PROSE_ELEMENTS


OVF_09_NAMESPACE = 'http://www.vmware.com/schema/ovf/1/envelope'
OVF_1_NAMESPACE = 'http://schemas.dmtf.org/ovf/envelope/1'
OVF_2_NAMESPACE = 'http://schemas.dmtf.org/ovf/envelope/2'
ENVELOPE_NAMESPACES = (OVF_09_NAMESPACE, OVF_1_NAMESPACE, OVF_2_NAMESPACE)

XML_NAMESPACE = 'http://www.w3.org/XML/1998/namespace'
XSI_NAMESPACE = 'http://www.w3.org/2001/XMLSchema-instance'
VBOX_NAMESPACE = 'http://www.virtualbox.org/ovf/machine'

# OVF 0.9 writes sections and virtual systems as generic elements typed by
# xsi:type, for example <Section xsi:type="ovf:EulaSection_Type">. An element
# with one of these local names in an envelope namespace, whose xsi:type
# resolves to <X>_Type in an envelope namespace, is path segment <X>.
TYPED_ELEMENTS = ('Section', 'Content')


def _envelope_attribute(local):
    """Every envelope namespace's attribute of this local name, as resolved names."""
    return tuple((namespace, local) for namespace in ENVELOPE_NAMESPACES)


# Ignored vendor elements which are replaced by an empty element, as
# (namespace URI, local name, attributes kept). The attributes kept are
# resolved names, (namespace URI or None, local name). This is an allow-list:
# anything not named here is dropped, along with every child.
EMPTIED_ELEMENTS = (
    # VirtualBox's machine configuration. It holds the exporting host's paths
    # and shared folders (found when the corpus was surveyed), and the parser ignores it
    # because it is marked not required.
    (VBOX_NAMESPACE, 'Machine', _envelope_attribute('required') + ((None, 'version'),)),
)

# The parser's scrub() replaces the same prose in a model with the same text.
PLACEHOLDER = prose.PLACEHOLDER.encode('utf-8')
TOOL_NAME = 'tools/trim-ovf-descriptor.py'
COMMENT_TEMPLATE = (
    '<!-- Trimmed from {source} (SHA-256 {digest} of the original descriptor) by ' + TOOL_NAME +
    '; prose replaced with "' + prose.PLACEHOLDER + '". -->')
_COMMENT_BEFORE, _COMMENT_REST = COMMENT_TEMPLATE.split('{source}')
_COMMENT_MIDDLE, _COMMENT_AFTER = _COMMENT_REST.split('{digest}')
COMMENT_RE = re.compile(
    (re.escape(_COMMENT_BEFORE) + '(?P<source>.*)' + re.escape(_COMMENT_MIDDLE) + '(?P<digest>[0-9a-f]{64})'
     + re.escape(_COMMENT_AFTER)).encode('utf-8'),
    re.DOTALL)

UTF8_BOM = b'\xef\xbb\xbf'
XML_WHITESPACE = b' \t\r\n'

# The prose elements' paths, without the model fields this tool has no use for.
# Each is matched against the tail of an element's ancestry, each segment being
# an element in one of ENVELOPE_NAMESPACES.
_PROSE_PATHS = tuple(tuple(path.split('/')) for path, _ in PROSE_ELEMENTS)
_EMPTIED = {(namespace, local): frozenset(kept) for namespace, local, kept in EMPTIED_ELEMENTS}


class TrimError(Exception):
    """The input cannot be trimmed, or the tool was misused."""


class CheckError(Exception):
    """A trimmed descriptor breaks the trimming rule."""

    def __init__(self, offset, element, reason):
        self.offset = offset
        self.element = element
        self.reason = reason
        super(CheckError, self).__init__(
            'offset %d of the trimmed file, element %s: %s' % (offset, element, reason))


class _Element(object):
    def __init__(self, qname, name, segment, start, tag_end, self_closing, attributes, parent):
        self.qname = qname                # the start tag's name, as bytes
        self.name = name                  # (namespace URI or None, local name)
        self.segment = segment            # name, after the xsi:type rule
        self.start = start                # offset of the start tag's '<'
        self.tag_end = tag_end            # offset just after the start tag's '>'
        self.self_closing = self_closing
        self.attributes = attributes      # [(resolved name or None, qname, span start, span end)]
        self.parent = parent
        self.end = None                   # offset just after the element's last byte
        self.content_end = None           # offset of the end tag's '<'

    def path(self):
        names = []
        element = self
        while element is not None:
            names.append(element.qname.decode('utf-8'))
            element = element.parent
        return '/' + '/'.join(reversed(names))


class Span(object):
    """A region of a descriptor that trimming replaces.

    kind is 'prose' (start and end bound the element's content) or 'emptied'
    (start and end bound the whole element).
    """

    def __init__(self, kind, start, end, element):
        self.kind = kind
        self.start = start
        self.end = end
        self.element = element

    def __repr__(self):
        return 'Span(%r, %d, %d, %r)' % (self.kind, self.start, self.end, self.element.path())


class Descriptor(object):
    """The byte offsets trimming needs, found in one descriptor."""

    def __init__(self, data, spans, elements, insertion_point, insert_after_declaration):
        self.data = data
        self.spans = spans
        self.elements = elements
        self.insertion_point = insertion_point
        self.insert_after_declaration = insert_after_declaration

    def element_at(self, offset):
        """The path of the innermost element holding offset."""
        best = None
        for element in self.elements:
            if element.start <= offset < element.end:
                if best is None or element.start > best.start:
                    best = element
        if best is None:
            return '(outside the root element)'
        return best.path()


def _scan_start_tag(data, offset):
    """Tokenise the start tag beginning at offset.

    Returns the tag's qualified name, its attributes as (qualified name, span
    start, span end), the offset just after its closing '>', and whether it is
    an empty-element tag. An attribute's span runs from the whitespace before
    its name to its closing quote, so that the spans of the attributes kept can
    be concatenated after the element's name. Quoted values are skipped whole,
    because they may contain '>'.
    """
    if data[offset:offset + 1] != b'<':
        raise TrimError('offset %d: expected a start tag' % offset)
    length = len(data)
    i = offset + 1
    while i < length and data[i] not in b' \t\r\n/>':
        i += 1
    qname = data[offset + 1:i]
    attributes = []
    while True:
        space_start = i
        while i < length and data[i] in XML_WHITESPACE:
            i += 1
        if i >= length:
            raise TrimError('offset %d: unterminated start tag' % offset)
        if data[i:i + 1] == b'>':
            return qname, attributes, i + 1, False
        if data[i:i + 2] == b'/>':
            return qname, attributes, i + 2, True
        if i == space_start:
            raise TrimError('offset %d: no whitespace before an attribute' % i)
        name_start = i
        while i < length and data[i] not in b' \t\r\n=/>':
            i += 1
        name = data[name_start:i]
        while i < length and data[i] in XML_WHITESPACE:
            i += 1
        if data[i:i + 1] != b'=':
            raise TrimError('offset %d: expected "=" after an attribute name' % i)
        i += 1
        while i < length and data[i] in XML_WHITESPACE:
            i += 1
        quote = data[i:i + 1]
        if quote not in (b'"', b"'"):
            raise TrimError('offset %d: expected a quoted attribute value' % i)
        close = data.find(quote, i + 1)
        if close < 0:
            raise TrimError('offset %d: unterminated attribute value' % i)
        i = close + 1
        attributes.append((name, space_start, i))


def _resolve_qname(value, scope):
    """Resolve a QName-valued attribute such as xsi:type, or return None."""
    value = value.strip()
    if ':' in value:
        prefix, local = value.split(':', 1)
        namespace = scope.get(prefix)
        if not namespace:
            return None
    else:
        local = value
        namespace = scope.get(None) or None
    return namespace, local


def _is_prose(stack):
    for path in _PROSE_PATHS:
        if len(path) > len(stack):
            continue
        tail = stack[-len(path):]
        if all(element.segment[0] in ENVELOPE_NAMESPACES and element.segment[1] == local
               for element, local in zip(tail, path)):
            return True
    return False


class _SpanCollector(xml.sax.handler.ContentHandler):
    def __init__(self, data, reader):
        xml.sax.handler.ContentHandler.__init__(self)
        self.data = data
        self.reader = reader
        self.stack = []
        self.scopes = [{'xml': XML_NAMESPACE}]
        self.pending_scope = {}
        self.elements = []
        self.spans = []

    def _byte_index(self):
        # The SAX interface reports only line and column. The offset comes from
        # the underlying expat parser, which is current while a handler runs.
        return self.reader._parser.CurrentByteIndex

    def startPrefixMapping(self, prefix, uri):
        self.pending_scope[prefix] = uri

    def startElementNS(self, name, qname, attrs):
        offset = self._byte_index()
        scope = dict(self.scopes[-1])
        scope.update(self.pending_scope)
        self.pending_scope = {}
        self.scopes.append(scope)

        tag_qname, raw_attributes, tag_end, self_closing = _scan_start_tag(self.data, offset)
        if tag_qname.decode('utf-8').split(':')[-1] != name[1]:
            raise TrimError('offset %d: start tag %r does not match the parser\'s element %r'
                            % (offset, tag_qname, name[1]))

        # Pair each attribute found in the bytes with the parser's resolved
        # name for it. Namespace declarations are not attributes to the parser.
        by_qname = {}
        for resolved in attrs.getNames():
            by_qname[attrs.getQNameByName(resolved)] = resolved
        attributes = []
        for raw_name, span_start, span_end in raw_attributes:
            text = raw_name.decode('utf-8')
            if text == 'xmlns' or text.startswith('xmlns:'):
                attributes.append((None, raw_name, span_start, span_end))
            elif text in by_qname:
                attributes.append((by_qname.pop(text), raw_name, span_start, span_end))
            else:
                raise TrimError('offset %d: attribute %s is not one the parser reported' % (span_start, text))
        if by_qname:
            raise TrimError('offset %d: the parser reported attributes not found in the start tag: %s'
                            % (offset, ', '.join(sorted(by_qname))))

        segment = name
        if name[0] in ENVELOPE_NAMESPACES and name[1] in TYPED_ELEMENTS:
            try:
                xsi_type = attrs.getValue((XSI_NAMESPACE, 'type'))
            except KeyError:
                xsi_type = None
            if xsi_type is not None:
                resolved_type = _resolve_qname(xsi_type, scope)
                if (resolved_type and resolved_type[0] in ENVELOPE_NAMESPACES
                        and resolved_type[1].endswith('_Type')):
                    segment = (resolved_type[0], resolved_type[1][:-len('_Type')])

        parent = self.stack[-1] if self.stack else None
        element = _Element(tag_qname, name, segment, offset, tag_end, self_closing, attributes, parent)
        self.stack.append(element)
        self.elements.append(element)

    def endElementNS(self, name, qname):
        offset = self._byte_index()
        element = self.stack[-1]
        if element.self_closing:
            element.content_end = element.tag_end
            element.end = element.tag_end
        else:
            if self.data[offset:offset + 2] != b'</':
                raise TrimError('offset %d: expected an end tag' % offset)
            element.content_end = offset
            element.end = self.data.index(b'>', offset) + 1

        if _is_prose(self.stack) and element.content_end > element.tag_end:
            self.spans.append(Span('prose', element.tag_end, element.content_end, element))
        if element.name in _EMPTIED:
            self.spans.append(Span('emptied', element.start, element.end, element))

        self.stack.pop()
        self.scopes.pop()


def _check_encoding(data):
    """Refuse a descriptor that is not UTF-8, declared or detected."""
    if data.startswith((b'\xfe\xff', b'\xff\xfe')):
        raise TrimError('the descriptor has a UTF-16 or UTF-32 byte order mark; only UTF-8 is supported')
    if data[:4] in (b'\x00\x00\x00<', b'<\x00\x00\x00', b'\x00<\x00?', b'<\x00?\x00', b'\x4c\x6f\xa7\x94'):
        raise TrimError('the descriptor is not UTF-8 (it looks like UTF-16, UTF-32 or EBCDIC)')
    body = data[len(UTF8_BOM):] if data.startswith(UTF8_BOM) else data
    declaration = _declaration_length(body)
    if declaration:
        match = re.search(rb'\sencoding\s*=\s*(["\'])(.*?)\1', body[:declaration])
        if match and match.group(2).lower() != b'utf-8':
            raise TrimError('the descriptor declares encoding %s; only UTF-8 is supported'
                            % match.group(2).decode('ascii', 'replace'))
    try:
        data.decode('utf-8')
    except UnicodeDecodeError as e:
        raise TrimError('the descriptor is not valid UTF-8 at offset %d' % e.start)


def _declaration_length(body):
    """The length of the XML declaration at the start of body, or 0 if there is none."""
    if body.startswith(b'<?xml') and body[5:6] and body[5:6] in XML_WHITESPACE:
        end = body.find(b'?>')
        if end < 0:
            raise TrimError('the XML declaration is not terminated')
        return end + 2
    return 0


def find_spans(data):
    """Parse a descriptor and return the Descriptor of its trimming spans."""
    _check_encoding(data)

    reader = expatreader.create_parser()
    # In namespace mode the stdlib reader always asks expat for prefixes, so
    # attributes carry their qualified names (Python 3.7 to 3.13 alike), even
    # though it refuses the feature_namespace_prefixes flag itself.
    reader.setFeature(xml.sax.handler.feature_namespaces, True)
    collector = _SpanCollector(data, reader)
    reader.setContentHandler(collector)
    source = xml.sax.xmlreader.InputSource()
    source.setByteStream(io.BytesIO(data))
    try:
        reader.parse(source)
    except xml.sax.SAXParseException as e:
        raise TrimError('the descriptor is not well-formed XML: %s' % e)

    # A span inside another is subsumed by it: prose inside an emptied
    # element, or anything inside prose. No other overlap is possible.
    spans = []
    for span in sorted(collector.spans, key=lambda s: (s.start, -s.end)):
        if spans and span.start < spans[-1].end:
            if span.end > spans[-1].end:
                raise TrimError('spans %r and %r overlap' % (spans[-1], span))
            continue
        spans.append(span)

    prefix = len(UTF8_BOM) if data.startswith(UTF8_BOM) else 0
    declaration = _declaration_length(data[prefix:])
    return Descriptor(data, spans, collector.elements, prefix + declaration, declaration > 0)


def _check_source(source):
    if '--' in source or source.endswith('-'):
        raise TrimError('the source may not contain "--" or end in "-", which XML forbids in a comment')
    if any(ord(c) < 0x20 or 0x7f <= ord(c) < 0xa0 for c in source):
        raise TrimError('the source may not contain control characters')


def _comment(source, digest, after_declaration):
    comment = COMMENT_TEMPLATE.format(source=source, digest=digest).encode('utf-8')
    if after_declaration:
        return b'\n' + comment
    return comment + b'\n'


def _emptied_element(data, element):
    """The empty element that replaces element: its name and kept attributes, as the original's bytes."""
    kept = _EMPTIED[element.name]
    # The prefixes the result uses: its name's (None for the default
    # namespace) and each kept attribute's. Unprefixed attributes have no
    # namespace, so they need no declaration.
    needed_prefixes = set([element.qname.split(b':', 1)[0] if b':' in element.qname else None])
    for resolved, qname, _, _ in element.attributes:
        if resolved is not None and resolved in kept and b':' in qname:
            needed_prefixes.add(qname.split(b':', 1)[0])

    pieces = [b'<', element.qname]
    for resolved, qname, span_start, span_end in element.attributes:
        if resolved is None:
            # A namespace declaration, kept only when the name or a kept
            # attribute needs it.
            prefix = qname.split(b':', 1)[1] if b':' in qname else None
            if prefix not in needed_prefixes:
                continue
        elif resolved not in kept:
            continue
        pieces.append(data[span_start:span_end])
    pieces.append(b'/>')
    return b''.join(pieces)


def trim(data, source):
    """Return the trimmed form of the descriptor data."""
    _check_source(source)
    descriptor = find_spans(data)
    digest = hashlib.sha256(data).hexdigest()

    pieces = [data[:descriptor.insertion_point],
              _comment(source, digest, descriptor.insert_after_declaration)]
    position = descriptor.insertion_point
    for span in descriptor.spans:
        pieces.append(data[position:span.start])
        if span.kind == 'prose':
            pieces.append(PLACEHOLDER)
        else:
            pieces.append(_emptied_element(data, span.element))
        position = span.end
    pieces.append(data[position:])
    trimmed = b''.join(pieces)

    # Never write a file the checker would reject.
    check(data, trimmed)
    return trimmed


def _compare(original, o_start, o_end, trimmed, t_start, t_end, descriptor, what):
    """Require original[o_start:o_end] == trimmed[t_start:t_end], else fail at the first difference."""
    a = original[o_start:o_end]
    b = trimmed[t_start:t_end]
    if a == b:
        return
    i = 0
    limit = min(len(a), len(b))
    while i < limit and a[i] == b[i]:
        i += 1
    offset = t_start + i
    raise CheckError(offset, descriptor.element_at(offset),
                     '%s differs from the original (original offset %d)' % (what, o_start + i))


def check(original, trimmed):
    """Raise CheckError unless trimmed is exactly original trimmed by the rules in the module docstring.

    Returns the Descriptor of the original.
    """
    try:
        before = find_spans(original)
    except TrimError as e:
        raise TrimError('the original: %s' % e)
    try:
        after = find_spans(trimmed)
    except TrimError as e:
        raise CheckError(0, '(none)', 'the trimmed file cannot be read: %s' % e)

    # The provenance comment, at the original's insertion point.
    ip = before.insertion_point
    _compare(original, 0, ip, trimmed, 0, ip, after, 'the prolog')
    comment_start = ip + 1 if before.insert_after_declaration else ip
    if before.insert_after_declaration and trimmed[ip:ip + 1] != b'\n':
        raise CheckError(ip, '(prolog)', 'expected a newline before the provenance comment')
    comment_end = trimmed.find(b'-->', comment_start)
    match = None
    if comment_end >= 0:
        comment_end += 3
        match = COMMENT_RE.fullmatch(trimmed, comment_start, comment_end)
    if not match:
        raise CheckError(comment_start, '(prolog)', 'expected the provenance comment')
    if match.group('digest').decode('ascii') != hashlib.sha256(original).hexdigest():
        raise CheckError(match.start('digest'), '(prolog)',
                         'the provenance comment names a SHA-256 other than the original\'s')
    if not before.insert_after_declaration:
        if trimmed[comment_end:comment_end + 1] != b'\n':
            raise CheckError(comment_end, '(prolog)', 'expected a newline after the provenance comment')
        comment_end += 1

    o_position = ip
    t_position = comment_end
    for index in range(min(len(before.spans), len(after.spans))):
        o_span = before.spans[index]
        t_span = after.spans[index]
        _compare(original, o_position, o_span.start, trimmed, t_position, t_span.start, after,
                 'a byte outside the trimmed spans')
        element = t_span.element.path()
        if o_span.kind != t_span.kind or o_span.element.path() != element:
            raise CheckError(t_span.start, element, 'expected the %s span of %s here'
                             % (o_span.kind, o_span.element.path()))
        if t_span.kind == 'prose':
            if trimmed[t_span.start:t_span.end] != PLACEHOLDER:
                raise CheckError(t_span.start, element, 'prose content is not "%s"' % prose.PLACEHOLDER)
        else:
            _check_emptied(original, o_span, trimmed, t_span)
        o_position = o_span.end
        t_position = t_span.end

    if len(before.spans) != len(after.spans):
        if len(before.spans) > len(after.spans):
            o_span = before.spans[len(after.spans)]
            # Locate the failure by comparing up to where the missing span should be.
            _compare(original, o_position, o_span.start, trimmed, t_position, len(trimmed), after,
                     'a byte outside the trimmed spans')
            offset = t_position + o_span.start - o_position
            raise CheckError(offset, after.element_at(offset), 'the %s span of %s was not trimmed'
                             % (o_span.kind, o_span.element.path()))
        t_span = after.spans[len(before.spans)]
        _compare(original, o_position, len(original), trimmed, t_position, t_span.start, after,
                 'a byte outside the trimmed spans')
        raise CheckError(t_span.start, t_span.element.path(),
                         'a %s span with no counterpart in the original' % t_span.kind)

    _compare(original, o_position, len(original), trimmed, t_position, len(trimmed), after,
             'a byte outside the trimmed spans')
    return before


def _check_emptied(original, o_span, trimmed, t_span):
    element = t_span.element
    path = element.path()
    kept = _EMPTIED[element.name]
    for resolved, qname, span_start, span_end in element.attributes:
        if resolved is not None and resolved not in kept:
            raise CheckError(span_start, path, 'attribute %s is not one the emptied list keeps'
                             % qname.decode('utf-8'))
    if not element.self_closing:
        raise CheckError(element.tag_end, path, 'an emptied element must be an empty-element tag, with no content')
    expected = _emptied_element(original, o_span.element)
    actual = trimmed[t_span.start:t_span.end]
    if expected != actual:
        i = 0
        while i < min(len(expected), len(actual)) and expected[i] == actual[i]:
            i += 1
        raise CheckError(t_span.start + i, path,
                         'the emptied element is not its original name and kept attributes, byte for byte')


def _read(path):
    with open(path, 'rb') as f:
        return f.read()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='Trim prose and host details from a vendor OVF descriptor, or check a trimmed copy.',
        usage='%(prog)s --source TEXT ORIGINAL OUTPUT\n       %(prog)s --check ORIGINAL TRIMMED')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--source', metavar='TEXT',
                      help='where the original came from, recorded in the provenance comment')
    mode.add_argument('--check', action='store_true',
                      help='check that TRIMMED is ORIGINAL trimmed by this tool\'s rule')
    parser.add_argument('original', metavar='ORIGINAL')
    parser.add_argument('other', metavar='OUTPUT|TRIMMED')
    args = parser.parse_args(argv)

    try:
        original = _read(args.original)
        if args.check:
            descriptor = check(original, _read(args.other))
            print('%s: check passed (%d prose spans, %d emptied elements)'
                  % (args.other, sum(1 for s in descriptor.spans if s.kind == 'prose'),
                     sum(1 for s in descriptor.spans if s.kind == 'emptied')))
        else:
            trimmed = trim(original, args.source)
            with open(args.other, 'wb') as f:
                f.write(trimmed)
    except CheckError as e:
        sys.stderr.write('%s: check failed at %s\n' % (args.other, e))
        return 1
    except (TrimError, OSError) as e:
        sys.stderr.write('error: %s\n' % e)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
