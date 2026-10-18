#!/usr/bin/env python3
"""Classify the upstream OVF descriptor corpora and choose the curated list.

The corpora are fetched by tools/fetch-descriptor-corpus.sh. Each is named on
the command line as NAME=DIRECTORY[:N], where DIRECTORY is the pinned
subdirectory and N, if given, overrides --curate for that corpus.

With no --curate the tool prints each corpus's shape counts.
Parsing uses defusedxml, so a malformed descriptor and a descriptor that
declares a DOCTYPE or an entity are counted as their own shapes rather than
being expanded.

With --curate N the tool prints the curated list (the rule is the tool):
for each shape, the N smallest examples from distinct upstream directories,
after removing byte-identical copies (keeping the path inside a named
directory, else the first in sorted order), plus the smallest descriptor in
each directory named for a feature. Except for the "not well-formed" and
"unknown root namespace" shapes, a candidate must hold at least one virtual
system and must not sit under a Neg/ directory, so that an empty or
deliberately broken file never stands for a shape.

--overrides FILE then applies a reviewer's changes. Each line is
'+NAME:PATH' or '-NAME:PATH', a tab, and a reason; blank lines and lines
starting with '#' are ignored. The tab is the separator because upstream
paths contain spaces. An override which names a path that does not exist, a
removal of a path the rule did not choose, or an addition of one it did, is an
error, so a pin bump cannot leave a stale override behind.

The output is one 'NAME:PATH' per line, sorted within each corpus, with paths
relative to DIRECTORY. --output FILE writes it there instead of stdout.

To regenerate shakenfist_client_ova/corpus_tests/curated.txt from the repository
root, take the pinned directories from the fetch script, which is the only place
the pins are written:

    tools/fetch-descriptor-corpus.sh
    pin() { sed -n "s/^$1=//p" tools/fetch-descriptor-corpus.sh; }
    tools/classify-ovf-corpus.py --curate 2 \\
        --overrides shakenfist_client_ova/corpus_tests/curated-overrides.txt \\
        --output shakenfist_client_ova/corpus_tests/curated.txt \\
        govmomi=.cache/ovf-corpora/govmomi-$(pin GOVMOMI_SHA)/$(pin GOVMOMI_PATH) \\
        cot=.cache/ovf-corpora/cot-$(pin COT_SHA)/$(pin COT_PATH):1

The descriptor corpus tests run the same command (shakenfist_client_ova/corpus_tests/
test_descriptor_corpus.py) and fail if its output is not curated.txt byte for byte.
"""

import argparse
import collections
import hashlib
import os
import re
import sys

from defusedxml import DefusedXmlException
from defusedxml import ElementTree


OVF_09_NAMESPACE = 'http://www.vmware.com/schema/ovf/1/envelope'
OVF_1_NAMESPACE = 'http://schemas.dmtf.org/ovf/envelope/1'
OVF_2_NAMESPACE = 'http://schemas.dmtf.org/ovf/envelope/2'
VCLOUD_NAMESPACE = 'http://www.vmware.com/vcloud/v1.5'

FEATURES = (
    'DeploymentOptionSection', 'VirtualSystemCollection', 'ProductSection', 'EulaSection', 'StartupSection',
    'OperatingSystemSection', 'AnnotationSection', 'ResourceAllocationSection', 'InstallSection',
    'EthernetPortItem', 'StorageItem', 'NetworkSection', 'DiskSection')
ATTRIBUTES = ('compression', 'chunkSize', 'configuration', 'transport', 'required')

# Directories named for a feature: each contributes its smallest descriptor.
NAMED_DIRECTORIES = (
    'MultiVmVapps', 'NonAsciiChars', 'OvfWithSpaceInFileName', 'SignedOVF', 'VM_with_nvram', 'OVFCerts',
    'property-types', 'qualifiers', 'virtualsystemcollection', 'vmware', 'BitnamiTomcat', 'PhotonOS',
    'OVFToolTemplates')

# The shapes whose representatives need not hold a system, because the file is
# the point: it is broken, or it is not OVF.
NEGATIVE_SHAPES = ('not-well-formed', 'refused-dtd-or-entity', 'unknown-root-namespace')

KNOWN_ROOTS = (OVF_1_NAMESPACE, OVF_2_NAMESPACE, OVF_09_NAMESPACE)


class Descriptor(object):
    """One .ovf file and what the classifier saw in it."""

    def __init__(self, path, raw):
        self.path = path  # Relative to the corpus directory, with '/' separators.
        self.size = len(raw)
        self.digest = hashlib.sha256(raw).hexdigest()
        self.error = None  # 'ParseError', or the name of a defusedxml refusal.
        self.root_namespace = ''
        self.namespaces = set()
        self.features = []
        self.systems = 0
        self.disks = 0
        self._classify(raw)

    def _classify(self, raw):
        try:
            root = ElementTree.fromstring(raw, forbid_dtd=True)
        except ElementTree.ParseError:
            self.error = 'ParseError'
            return
        except DefusedXmlException as e:
            self.error = type(e).__name__
            return

        match = re.match(r'\{(.*)\}', root.tag)
        self.root_namespace = match.group(1) if match else ''
        tags = collections.Counter()
        attributes = set()
        for element in root.iter():
            if not isinstance(element.tag, str):
                continue
            match = re.match(r'\{(.*)\}(.*)', element.tag)
            if match:
                self.namespaces.add(match.group(1))
                tags[match.group(2)] += 1
            for key, value in element.attrib.items():
                name = re.sub(r'\{.*\}', '', key)
                if name in ATTRIBUTES:
                    attributes.add('%s=%s' % (name, value) if name == 'required' else name)
        self.features = [f for f in FEATURES if tags[f]] + sorted(attributes)
        self.systems = tags['VirtualSystem']
        self.disks = tags['Disk']

    def has_system(self):
        # OVF 0.9 holds its systems in <Content xsi:type="ovf:VirtualSystem_Type">,
        # which the VirtualSystem count does not see.
        return self.systems > 0 or self.root_namespace == OVF_09_NAMESPACE

    def parsed(self):
        return self.error is None


# Each shape is a name and a predicate. These are the shapes of survey
# finding 6 plus the features the parser has a rule for.
SHAPES = (
    ('not-well-formed', lambda d: d.error == 'ParseError'),
    ('refused-dtd-or-entity', lambda d: d.error not in (None, 'ParseError')),
    ('ovf-0.9', lambda d: d.root_namespace == OVF_09_NAMESPACE),
    ('ovf-2', lambda d: d.root_namespace == OVF_2_NAMESPACE),
    ('ovf-1-mentioning-2', lambda d: d.root_namespace == OVF_1_NAMESPACE and OVF_2_NAMESPACE in d.namespaces),
    ('unknown-root-namespace', lambda d: d.parsed() and d.root_namespace not in KNOWN_ROOTS),
    ('virtual-system-collection', lambda d: 'VirtualSystemCollection' in d.features),
    ('deployment-options', lambda d: 'DeploymentOptionSection' in d.features and 'configuration' in d.features),
    ('eula', lambda d: 'EulaSection' in d.features),
    ('product-properties', lambda d: 'ProductSection' in d.features and 'transport' in d.features),
    ('startup', lambda d: 'StartupSection' in d.features),
    ('resource-allocation', lambda d: 'ResourceAllocationSection' in d.features),
    ('install', lambda d: 'InstallSection' in d.features),
    ('compression', lambda d: 'compression' in d.features),
    ('chunked', lambda d: 'chunkSize' in d.features),
    ('epasd-sasd', lambda d: 'StorageItem' in d.features or 'EthernetPortItem' in d.features),
    ('several-disks', lambda d: d.disks > 2 and 'VirtualSystemCollection' not in d.features),
    ('vcloud', lambda d: VCLOUD_NAMESPACE in d.namespaces),
    ('required-false', lambda d: 'required=false' in d.features and 'VirtualSystemCollection' not in d.features),
    # A plain OVF 1.x descriptor uses at most three of the features above.
    ('plain-1.x', lambda d: d.root_namespace == OVF_1_NAMESPACE and len(d.features) <= 3),
)

# The counts survey finding 6 reports, which are not all curation shapes.
SURVEY = (
    ('OVF 1.x root namespace', lambda d: d.root_namespace == OVF_1_NAMESPACE),
    ('OVF 0.9 root namespace', lambda d: d.root_namespace == OVF_09_NAMESPACE),
    ('OVF 2.x root namespace', lambda d: d.root_namespace == OVF_2_NAMESPACE),
    ('OVF 1.x files that mention 2.x', lambda d: d.root_namespace == OVF_1_NAMESPACE
     and OVF_2_NAMESPACE in d.namespaces),
    ('Unknown root namespace', lambda d: d.parsed() and d.root_namespace not in KNOWN_ROOTS),
    ('Not well-formed XML (ParseError)', lambda d: d.error == 'ParseError'),
    ('DOCTYPE or entity declarations (refused)', lambda d: d.error not in (None, 'ParseError')),
    ('VirtualSystemCollection', lambda d: 'VirtualSystemCollection' in d.features),
    ('ovf:required="false" somewhere', lambda d: 'required=false' in d.features),
    ('ProductSection', lambda d: 'ProductSection' in d.features),
    ('EulaSection', lambda d: 'EulaSection' in d.features),
    ('DeploymentOptionSection with ovf:configuration', lambda d: 'DeploymentOptionSection' in d.features
     and 'configuration' in d.features),
    ('ovf:compression', lambda d: 'compression' in d.features),
    ('ovf:chunkSize', lambda d: 'chunkSize' in d.features),
)


def load(directory):
    """Read every .ovf under directory, as untrusted bytes, in sorted order."""
    found = []
    for base, _, names in os.walk(directory):
        for name in names:
            if name.endswith('.ovf'):
                full = os.path.join(base, name)
                with open(full, 'rb') as f:
                    raw = f.read()
                found.append(Descriptor(os.path.relpath(full, directory).replace(os.sep, '/'), raw))
    return sorted(found, key=lambda d: d.path)


def named_directory(descriptor):
    """The named directory a descriptor sits in, or None."""
    # A named directory is a top-level directory or file (qualifiers.ovf),
    # or a directory directly under external/. The match is exact, so that a
    # later upstream vmware-foo.ovf does not count as being in vmware.
    parts = descriptor.path.split('/')
    for name in NAMED_DIRECTORIES:
        if parts[0] in (name, name + '.ovf') or (parts[0] == 'external' and len(parts) > 2 and parts[1] == name):
            return name
    return None


def deduplicate(descriptors):
    """Drop byte-identical copies, keeping one path per group.

    The kept path is one inside a named directory if there is such a path,
    else the first in sorted order. Input is sorted, and the output is too.
    """
    groups = collections.OrderedDict()
    for d in descriptors:
        groups.setdefault(d.digest, []).append(d)
    kept = []
    for group in groups.values():
        in_named = [d for d in group if named_directory(d)]
        kept.append((in_named or group)[0])
    return sorted(kept, key=lambda d: d.path)


def upstream_directory(descriptor):
    """The upstream directory a descriptor counts as coming from.

    Under external/ that is the first directory below it, else the first path
    element (a top-level file counts as its own directory).
    """
    parts = descriptor.path.split('/')
    return '/'.join(parts[:2]) if parts[0] == 'external' else parts[0]


def representative(descriptor, shape):
    if shape in NEGATIVE_SHAPES:
        return True
    return '/Neg/' not in '/' + descriptor.path + '/' and descriptor.has_system()


def curate(descriptors, per_shape):
    """Return {path: [reasons]} for the rule's choice over deduplicated descriptors."""
    chosen = collections.OrderedDict()
    for shape, predicate in SHAPES:
        seen = set()
        for d in sorted((d for d in descriptors if predicate(d) and representative(d, shape)),
                        key=lambda d: (d.size, d.path)):
            if upstream_directory(d) in seen:
                continue
            seen.add(upstream_directory(d))
            chosen.setdefault(d.path, []).append(shape)
            if len(seen) >= per_shape:
                break
    for name in NAMED_DIRECTORIES:
        candidates = sorted((d for d in descriptors if named_directory(d) == name), key=lambda d: (d.size, d.path))
        if candidates:
            chosen.setdefault(candidates[0].path, []).append('named:' + name)
    return chosen


def read_overrides(filename):
    """Parse an overrides file into a list of (sign, corpus, path, reason)."""
    overrides = []
    with open(filename, encoding='utf-8') as f:
        for number, line in enumerate(f, 1):
            line = line.rstrip('\n')
            if not line.strip() or line.startswith('#'):
                continue
            where = '%s:%d' % (filename, number)
            spec, tab, reason = line.partition('\t')
            if not tab or not reason.strip():
                raise ValueError('%s: want "+NAME:PATH", a tab, and a reason' % where)
            if spec[:1] not in ('+', '-') or ':' not in spec:
                raise ValueError('%s: want "+NAME:PATH" or "-NAME:PATH", got %r' % (where, spec))
            corpus, _, path = spec[1:].partition(':')
            if not corpus or not path:
                raise ValueError('%s: empty corpus name or path in %r' % (where, spec))
            overrides.append((spec[0], corpus, path, reason.strip()))
    return overrides


def apply_overrides(selected, overrides, corpora):
    """Apply overrides to {corpus: set(path)} in place. corpora is {name: [Descriptor]}."""
    for sign, corpus, path, reason in overrides:
        spec = '%s%s:%s' % (sign, corpus, path)
        if corpus not in selected:
            raise ValueError('%s: no such corpus' % spec)
        if sign == '+':
            if path not in {d.path for d in corpora[corpus]}:
                raise ValueError('%s: no such descriptor in the corpus' % spec)
            if path in selected[corpus]:
                raise ValueError('%s: the rule already chose it' % spec)
            selected[corpus].add(path)
        else:
            if path not in selected[corpus]:
                raise ValueError('%s: the rule did not choose it' % spec)
            selected[corpus].discard(path)


def summarise(name, descriptors):
    distinct = deduplicate(descriptors)
    print('%s: %d descriptors, %d distinct' % (name, len(descriptors), len(distinct)))
    print('  %-50s %6s %9s' % ('shape', 'all', 'distinct'))
    for label, predicate in SURVEY:
        print('  %-50s %6d %9d' % (label, sum(1 for d in descriptors if predicate(d)),
                                   sum(1 for d in distinct if predicate(d))))
    print()


def parse_corpus_spec(spec, default):
    name, equals, rest = spec.partition('=')
    if not equals or not name or not rest:
        raise ValueError('%r: want NAME=DIRECTORY[:N]' % spec)
    directory, colon, number = rest.rpartition(':')
    if colon and number.isdigit():
        return name, directory, int(number)
    return name, rest, default


def main(argv=None):
    parser = argparse.ArgumentParser(description='Classify OVF descriptor corpora and choose the curated list.')
    parser.add_argument('--curate', type=int, metavar='N',
                        help='print the curated list, N examples per shape unless a corpus says otherwise')
    parser.add_argument('--overrides', metavar='FILE', help='apply reviewer overrides to the curated list')
    parser.add_argument('--output', metavar='FILE', help='write the curated list here instead of to stdout')
    parser.add_argument('corpora', nargs='+', metavar='NAME=DIRECTORY[:N]')
    args = parser.parse_args(argv)

    try:
        specs = [parse_corpus_spec(s, args.curate) for s in args.corpora]
        if len(set(s[0] for s in specs)) != len(specs):
            raise ValueError('corpus names must be distinct')
        if args.overrides and args.curate is None:
            raise ValueError('--overrides needs --curate')
        overrides = read_overrides(args.overrides) if args.overrides else []

        corpora = collections.OrderedDict((name, load(directory)) for name, directory, _ in specs)
        if args.curate is None:
            for name, descriptors in corpora.items():
                summarise(name, descriptors)
            return 0

        selected = collections.OrderedDict()
        for name, _, per_shape in specs:
            selected[name] = set(curate(deduplicate(corpora[name]), per_shape))
        apply_overrides(selected, overrides, corpora)
    except (OSError, ValueError) as e:
        print('error: %s' % e, file=sys.stderr)
        return 1

    lines = ['%s:%s' % (name, path) for name, paths in selected.items() for path in sorted(paths)]
    text = ''.join(line + '\n' for line in lines)
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
