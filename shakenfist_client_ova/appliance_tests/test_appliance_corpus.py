"""The appliance corpus tier: open_package(), the digest checks and the import command against real appliances.

The corpus is the downloaded/ova directory of an instar-testdata checkout, named by the APPLIANCE_CORPUS environment
variable. It holds <name>.ova for each appliance and <name>.provenance.json beside it, whose "kind" is "whole" or
"descriptor-only". A descriptor-only appliance is the original's descriptor and manifest re-tarred without its disks,
and its provenance lists the members left out as "absent_members". Run the tier with "tox -eappliance-corpus". It
lives outside .stestr.conf's test_path so that the offline unit tier never collects it.

Each appliance has two tests, named after it. The first expects:

* for an appliance named in expected.json, the open to fail with the outcome name given there;
* for a whole appliance, the open to succeed, every disk with a manifest entry to match its digest, and the import
  command, with the client mocked, to exit 0 having uploaded each disk once as "<system id>-<disk id>";
* for a descriptor-only appliance, the open to fail with MissingMemberError, naming exactly its absent_members. The
  order of the names is not part of that: it is the order the corpus happens to list them in.

The second, ending in _fixture, expects the appliance's descriptor, as open_package() reads it from the OVA, and its
trimmed copy in tests/fixtures/ovf/vendor/<name>.ovf to give the same model once prose.scrub() has replaced the prose
in each, compared as to_json() writes them. Where the parser refuses the descriptor, as it does for the appliances
named in expected.json, the two must be refused with the same outcome name instead. Every appliance must have a
trimmed fixture and every trimmed fixture an appliance.

The corpus is private. Assertion messages carry appliance, artifact and outcome names and counts only, never a
member's name, an exception's message or the command's output, any of which can quote the archive.

If the corpus is missing or incomplete these tests fail, never skip: a missing corpus must not look like a clean run.
"""

import collections
import contextlib
import json
import os
import re
from unittest import mock

from click.testing import CliRunner
from shakenfist_client import apiclient
import testtools

import shakenfist_client_ova as ova
from shakenfist_client_ova import ovf
from shakenfist_client_ova.ovf import prose


HERE = os.path.dirname(os.path.abspath(__file__))
EXPECTED = os.path.join(HERE, 'expected.json')

CORPUS_VARIABLE = 'APPLIANCE_CORPUS'
OVA_SUFFIX = '.ova'
PROVENANCE_SUFFIX = '.provenance.json'

# The trimmed copy of each appliance's descriptor, <name>.ovf, which the unit tier tests.
VENDOR_FIXTURES = os.path.join(os.path.dirname(HERE), 'tests', 'fixtures', 'ovf', 'vendor')
FIXTURE_SUFFIX = '.ovf'

# What a file Git LFS has not fetched starts with: the pointer it holds in place of the content.
LFS_POINTER_PREFIX = b'version https://git-lfs.github.com/spec/'

# The upload stand-in reads a disk in pieces of this size.
READ_SIZE = 1024 * 1024

# The namespace the mocked client is authenticated to.
NAMESPACE = 'appliance-corpus'


class CorpusUnavailable(Exception):
    pass


def method_name(name):
    """The name of an appliance's test method."""
    return 'test_' + re.sub(r'[^A-Za-z0-9]', '_', name)


def fixture_method_name(name):
    """The name of the method testing an appliance's trimmed fixture."""
    return method_name(name) + '_fixture'


def corpus_directory():
    """The directory APPLIANCE_CORPUS names, or raise CorpusUnavailable."""
    directory = os.environ.get(CORPUS_VARIABLE)
    if not directory:
        raise CorpusUnavailable('%s is not set' % CORPUS_VARIABLE)
    if not os.path.isdir(directory):
        raise CorpusUnavailable('%s does not name a directory' % CORPUS_VARIABLE)
    return directory


def _stems(directory, suffix):
    return sorted(name[:-len(suffix)] for name in os.listdir(directory) if name.endswith(suffix))


def _is_lfs_pointer(path):
    with open(path, 'rb') as f:
        return f.read(len(LFS_POINTER_PREFIX)) == LFS_POINTER_PREFIX


def appliances():
    """The corpus directory and the name of every appliance in it, or raise CorpusUnavailable.

    The corpus is complete when it holds at least one OVA, no OVA is a Git LFS
    pointer, and every OVA has a provenance file and every provenance file an
    OVA.
    """
    directory = corpus_directory()
    names = _stems(directory, OVA_SUFFIX)
    if not names:
        raise CorpusUnavailable('the directory %s names holds no %s file' % (CORPUS_VARIABLE, OVA_SUFFIX))

    pointers = [name for name in names if _is_lfs_pointer(os.path.join(directory, name + OVA_SUFFIX))]
    if pointers:
        raise CorpusUnavailable('these OVAs are Git LFS pointers, not archives: %s; run "git lfs pull"'
                                % ', '.join(pointers))

    provenance = _stems(directory, PROVENANCE_SUFFIX)
    unrecorded = sorted(set(names) - set(provenance))
    if unrecorded:
        raise CorpusUnavailable('these OVAs have no %s file: %s' % (PROVENANCE_SUFFIX, ', '.join(unrecorded)))
    orphaned = sorted(set(provenance) - set(names))
    if orphaned:
        raise CorpusUnavailable('these %s files have no OVA: %s' % (PROVENANCE_SUFFIX, ', '.join(orphaned)))

    tests = {}
    for name in names:
        for test in (method_name(name), fixture_method_name(name)):
            if test in tests:
                raise CorpusUnavailable('%s and %s would have the same test name' % (tests[test], name))
            tests[test] = name
    return directory, names


def read_expected():
    """The outcome name expected of each appliance named in expected.json."""
    with open(EXPECTED, encoding='utf-8') as f:
        return json.load(f)


def _attempt(function, *args):
    """function's result and None, or None and the outcome name of what it raised.

    The exception itself is not kept, so that a failure reported after this
    returns cannot show its message, even as the context of another exception.
    """
    try:
        return function(*args), None
    except Exception as e:
        return None, ovf.outcome_name(e)


def _read_bytes(path):
    with open(path, 'rb') as f:
        return f.read()


def _read_json(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def descriptor_bytes(path):
    """The bytes open_package() reads as the descriptor of the OVA at path, and None, or None and an outcome name.

    open_package() runs with its parse_descriptor() wrapped to keep the bytes
    it is given, so that the descriptor is found, and checked against the
    manifest, by the package's own rules. Whatever the open does after that,
    such as refusing a descriptor-only appliance for its missing disks, does
    not matter here. The outcome name is that of what the open raised before
    it reached the descriptor.
    """
    read = []

    def parse(data):
        read.append(data)
        return ovf.parse_descriptor(data)

    with mock.patch('shakenfist_client_ova.ovf.package.parse_descriptor', side_effect=parse):
        package, outcome = _attempt(ovf.open_package, path)
    if package is not None:
        package.close()
    if read:
        return read[0], None
    return None, outcome


def scrubbed_model(data):
    """to_json() of the model of descriptor bytes, its prose replaced by prose.scrub()."""
    envelope = ovf.parse_descriptor(data)
    prose.scrub(envelope)
    return ovf.to_json(envelope)


def _virtual_system_id(package):
    return package.envelope.virtual_system.id


class _Progress:
    """A stand-in for tqdm, so that the import draws no progress bar."""

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        pass

    def update(self, n):
        pass


class ApplianceCorpusTestCase(testtools.TestCase):
    """One test per appliance, added below, and one of the corpus. Each fails, rather than skips, without a corpus."""

    def setUp(self):
        super().setUp()
        try:
            self.directory, self.names = appliances()
        except CorpusUnavailable as e:
            self.fail(
                'The appliance corpus is missing or incomplete: %s. Set %s to the downloaded/ova directory of an '
                'instar-testdata checkout, with its LFS files pulled. These tests fail instead of skipping, so that '
                'a missing corpus cannot pass as a clean run.' % (e, CORPUS_VARIABLE))
        self.expected = read_expected()

    def test_corpus_is_complete(self):
        """Every expected.json entry still names an appliance in the corpus, and appliances and fixtures pair up.

        Whether the corpus itself is complete is checked in setUp, so that
        every test fails without it; this checks the expected outcomes and the
        trimmed fixtures against the appliances that are there. A fixture
        without its appliance could not be checked against its original.
        """
        stale = sorted(set(self.expected) - set(self.names))
        self.assertEqual([], stale, 'expected.json names appliances which are not in the corpus')
        fixtures = _stems(VENDOR_FIXTURES, FIXTURE_SUFFIX)
        untrimmed = sorted(set(self.names) - set(fixtures))
        self.assertEqual([], untrimmed, 'these appliances have no trimmed fixture')
        orphaned = sorted(set(fixtures) - set(self.names))
        self.assertEqual([], orphaned, 'these trimmed fixtures name no appliance in the corpus')

    def check_appliance(self, name):
        provenance, outcome = _attempt(_read_json, os.path.join(self.directory, name + PROVENANCE_SUFFIX))
        if outcome is not None:
            self.fail('%s: reading its provenance gives %s' % (name, outcome))
        if not isinstance(provenance, dict):
            self.fail('%s: its provenance is not a JSON object' % name)
        kind = provenance.get('kind')
        path = os.path.join(self.directory, name + OVA_SUFFIX)

        if name in self.expected:
            self.check_refused(name, path, self.expected[name])
        elif kind == 'whole':
            self.check_whole(name, path)
        elif kind == 'descriptor-only':
            absent = provenance.get('absent_members')
            if not isinstance(absent, list) or not absent:
                self.fail('%s: its provenance gives no list of absent_members' % name)
            self.check_descriptor_only(name, path, absent)
        else:
            self.fail('%s: its provenance kind is neither "whole" nor "descriptor-only"' % name)

    def check_refused(self, name, path, expected):
        package, outcome = _attempt(ovf.open_package, path)
        if package is not None:
            package.close()
            self.fail('%s: opens, but should give %s' % (name, expected))
        self.assertEqual(expected, outcome, '%s: the outcome of opening it' % name)

    def check_descriptor_only(self, name, path, absent):
        missing = None
        try:
            ovf.open_package(path).close()
            outcome = 'an open package'
        except ovf.MissingMemberError as e:
            missing = e.members
        except Exception as e:
            outcome = ovf.outcome_name(e)
        if missing is None:
            self.fail('%s: gives %s, but should give MissingMemberError' % (name, outcome))
        # Counted, not listed: a member's name comes from the archive.
        unnamed = sum((collections.Counter(absent) - collections.Counter(missing)).values())
        unexpected = sum((collections.Counter(missing) - collections.Counter(absent)).values())
        if unnamed or unexpected:
            self.fail('%s: MissingMemberError leaves out %d of its %d absent_members, and names %d members that are '
                      'not among them' % (name, unnamed, len(absent), unexpected))

    def check_whole(self, name, path):
        package, outcome = _attempt(ovf.open_package, path)
        if package is None:
            self.fail('%s: a whole appliance, but gives %s' % (name, outcome))
        with package:
            system_id, outcome = _attempt(_virtual_system_id, package)
            if outcome is not None:
                self.fail('%s: reading its VirtualSystem id gives %s' % (name, outcome))
            uploads = []
            members = [upload.member for upload in package.uploads]
            checked = 0
            for number, upload in enumerate(package.uploads, 1):
                size, outcome = _attempt(package.member_size, upload.member)
                if outcome is not None:
                    self.fail('%s: reading the size of disk %d gives %s' % (name, number, outcome))
                uploads.append(('%s-%s' % (system_id, upload.disk.disk_id), size))
                entry, outcome = _attempt(package.manifest_entry, upload.member)
                if outcome is not None:
                    self.fail('%s: finding the manifest entry of disk %d gives %s' % (name, number, outcome))
                if entry is None:
                    continue
                digests, outcome = _attempt(package.digests, upload.member, [entry.algorithm])
                if outcome is None:
                    _, outcome = _attempt(package.check_digest, upload.member, digests)
                if outcome is not None:
                    self.fail('%s: checking disk %d against the manifest gives %s' % (name, number, outcome))
                checked += 1
            # Otherwise a whole appliance would pass with no disk checked at all.
            if not checked:
                self.fail('%s: a whole appliance, but has no manifest entry for any disk' % name)

        self.assertEqual(uploads, self.run_import(name, path, members), '%s: what the import uploads' % name)

    def check_fixture(self, name):
        """The appliance's descriptor and its trimmed fixture give one scrubbed model, or one outcome name.

        Only whether they match is reported, never how they differ: the
        difference would be the descriptor's own text.
        """
        trimmed, outcome = _attempt(_read_bytes, os.path.join(VENDOR_FIXTURES, name + FIXTURE_SUFFIX))
        if outcome is not None:
            self.fail('%s: reading its trimmed fixture gives %s' % (name, outcome))
        original, outcome = descriptor_bytes(os.path.join(self.directory, name + OVA_SUFFIX))
        if outcome is not None:
            self.fail('%s: its descriptor cannot be read: the open gives %s' % (name, outcome))

        original_model, original_outcome = _attempt(scrubbed_model, original)
        trimmed_model, trimmed_outcome = _attempt(scrubbed_model, trimmed)
        if original_outcome != trimmed_outcome:
            self.fail('%s: its descriptor gives %s, but its trimmed fixture %s' % (
                name, original_outcome or 'a model', trimmed_outcome or 'a model'))
        if original_model != trimmed_model:
            self.fail('%s: the scrubbed models of its descriptor and its trimmed fixture differ' % name)

    def run_import(self, name, path, members):
        """Run ova import on the OVA at path with the client mocked, returning each upload's (name, bytes read).

        Every licence is accepted, the server has no artifact of any name, and
        it cannot search for a blob by hash, so that each disk is read through
        the upload into a new artifact. Each artifact must then be given the
        OVA's real path and its disk's member, of members, as metadata. The
        command's output is never shown, because it quotes the descriptor, and
        neither are the metadata values, of which a member name comes from the
        archive: they are compared, and only how many matched is reported.
        """
        uploads = []

        def not_found(artifact_ref):
            raise apiclient.ResourceNotFoundException('API request failed', 'GET', '/artifacts/' + artifact_ref, 404,
                                                      '{"error": "artifact not found", "status": 404}')

        def upload(client, artifact_name, f, size, *args, **kwargs):
            length = 0
            while True:
                data = f.read(READ_SIZE)
                if not data:
                    break
                length += len(data)
            uploads.append((artifact_name, length))
            return {'uuid': 'uploaded-' + artifact_name}

        with contextlib.ExitStack() as stack:
            client_class = stack.enter_context(mock.patch('shakenfist_client_ova.apiclient.Client'))
            util = stack.enter_context(mock.patch('shakenfist_client_ova.util'))
            stack.enter_context(mock.patch('shakenfist_client_ova.tqdm', _Progress))
            client = client_class.return_value
            client.namespace = NAMESPACE
            client.check_capability.return_value = False
            client.get_artifact.side_effect = not_found
            client.blob_artifact.side_effect = lambda name, blob_uuid: {'uuid': 'blob-' + name}
            client.set_artifact_metadata_item.return_value = None
            util.upload_artifact_with_progress_file_like_object.side_effect = upload
            result = CliRunner().invoke(ova.ova, ['import', path, '--accept-eula'], obj={})

        if result.exit_code != 0:
            raised = ''
            if result.exception is not None and not isinstance(result.exception, SystemExit):
                raised = ', raising %s' % ovf.outcome_name(result.exception)
            self.fail('%s: the import exits %d%s' % (name, result.exit_code, raised))

        # Counted rather than compared with assertEqual, whose mismatch would print the calls' arguments.
        if client.blob_artifact.called:
            self.fail('%s: the import makes %d artifacts from a blob, but the server cannot search for one'
                      % (name, client.blob_artifact.call_count))
        expected = []
        for (artifact_name, _), member in zip(uploads, members):
            uuid = 'uploaded-' + artifact_name
            expected.extend([(uuid, 'ova_file', os.path.realpath(path)), (uuid, 'ova_member', member)])
        calls = [call[0] for call in client.set_artifact_metadata_item.call_args_list]
        if calls != expected:
            matching = sum(1 for call, item in zip(calls, expected) if call == item)
            self.fail('%s: the import sets %d metadata items, %d of them as expected, where it should set %d'
                      % (name, len(calls), matching, len(expected)))
        return uploads


def _add_appliance_tests(cls):
    """Add a test to cls for each appliance in the corpus, so that a failure names the appliance.

    Without a complete corpus none is added, and test_corpus_is_complete
    fails, saying why.
    """
    try:
        _, names = appliances()
    except CorpusUnavailable:
        return
    for name in names:
        def test(self, name=name):
            self.check_appliance(name)
        test.__name__ = method_name(name)
        setattr(cls, test.__name__, test)

        def test_fixture(self, name=name):
            self.check_fixture(name)
        test_fixture.__name__ = fixture_method_name(name)
        setattr(cls, test_fixture.__name__, test_fixture)


_add_appliance_tests(ApplianceCorpusTestCase)
