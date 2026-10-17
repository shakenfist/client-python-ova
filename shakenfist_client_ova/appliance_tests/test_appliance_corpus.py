"""The appliance corpus tier: open_package(), the digest checks and the import command against real appliances.

The corpus is the downloaded/ova directory of an instar-testdata checkout, named by the APPLIANCE_CORPUS environment
variable. It holds <name>.ova for each appliance and <name>.provenance.json beside it, whose "kind" is "whole" or
"descriptor-only". A descriptor-only appliance is the original's descriptor and manifest re-tarred without its disks,
and its provenance lists the members left out as "absent_members". Run the tier with "tox -eappliance-corpus". It
lives outside .stestr.conf's test_path so that the offline unit tier never collects it.

Each appliance is one test, named after it, which expects:

* for an appliance named in expected.json, the open to fail with the outcome name given there;
* for a whole appliance, the open to succeed, every disk with a manifest entry to match its digest, and the import
  command, with the client mocked, to exit 0 having uploaded each disk once as "<system id>-<disk id>";
* for a descriptor-only appliance, the open to fail with MissingMemberError, naming exactly its absent_members.

The corpus is private. Assertion messages carry appliance names, artifact names and outcome names only, never an
exception's message or the command's output, either of which can quote the descriptor.

If the corpus is missing or incomplete these tests fail, never skip: a missing corpus must not look like a clean run.
"""

import contextlib
import json
import os
import re
from unittest import mock

from click.testing import CliRunner
import testtools

import shakenfist_client_ova as ova
from shakenfist_client_ova import ovf


HERE = os.path.dirname(os.path.abspath(__file__))
EXPECTED = os.path.join(HERE, 'expected.json')

CORPUS_VARIABLE = 'APPLIANCE_CORPUS'
OVA_SUFFIX = '.ova'
PROVENANCE_SUFFIX = '.provenance.json'

# What a file Git LFS has not fetched starts with: the pointer it holds in place of the content.
LFS_POINTER_PREFIX = b'version https://git-lfs.github.com/spec/'

# The upload stand-in reads a disk in pieces of this size.
READ_SIZE = 1024 * 1024


class CorpusUnavailable(Exception):
    pass


def method_name(name):
    """The name of an appliance's test method."""
    return 'test_' + re.sub(r'[^A-Za-z0-9]', '_', name)


def corpus_directory():
    """The directory APPLIANCE_CORPUS names, or raise CorpusUnavailable."""
    directory = os.environ.get(CORPUS_VARIABLE)
    if not directory:
        raise CorpusUnavailable('%s is not set' % CORPUS_VARIABLE)
    if not os.path.isdir(directory):
        raise CorpusUnavailable('%s is %s, which is not a directory' % (CORPUS_VARIABLE, directory))
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
        raise CorpusUnavailable('%s holds no %s file' % (directory, OVA_SUFFIX))

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
        if method_name(name) in tests:
            raise CorpusUnavailable('%s and %s would have the same test name' % (tests[method_name(name)], name))
        tests[method_name(name)] = name
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
        stale = sorted(set(self.expected) - set(self.names))
        self.assertEqual([], stale, 'expected.json names appliances which are not in the corpus')

    def check_appliance(self, name):
        with open(os.path.join(self.directory, name + PROVENANCE_SUFFIX), encoding='utf-8') as f:
            provenance = json.load(f)
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
            self.check_descriptor_only(name, path, tuple(absent))
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
        self.assertEqual(absent, missing, '%s: the members MissingMemberError names, and its absent_members' % name)

    def check_whole(self, name, path):
        package, outcome = _attempt(ovf.open_package, path)
        if package is None:
            self.fail('%s: a whole appliance, but gives %s' % (name, outcome))
        with package:
            system_id = package.envelope.virtual_system.id
            uploads = [('%s-%s' % (system_id, upload.disk.disk_id), package.member_size(upload.member))
                       for upload in package.uploads]
            for number, upload in enumerate(package.uploads, 1):
                entry = package.manifest_entry(upload.member)
                if entry is None:
                    continue
                digests, outcome = _attempt(package.digests, upload.member, [entry.algorithm])
                if outcome is None:
                    _, outcome = _attempt(package.check_digest, upload.member, digests)
                if outcome is not None:
                    self.fail('%s: checking disk %d against the manifest gives %s' % (name, number, outcome))

        self.assertEqual(uploads, self.run_import(name, path), '%s: what the import uploads' % name)

    def run_import(self, name, path):
        """Run ova import on the OVA at path with the client mocked, returning each upload's (name, bytes read).

        Every licence is accepted, and the server cannot search for a blob by
        hash, so that each disk is read through the upload. The command's
        output is never shown, because it quotes the descriptor.
        """
        uploads = []

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
            client_class.return_value.check_capability.return_value = False
            util.upload_artifact_with_progress_file_like_object.side_effect = upload
            result = CliRunner().invoke(ova.ova, ['import', path, '--accept-eula'], obj={})

        if result.exit_code != 0:
            raised = ''
            if result.exception is not None and not isinstance(result.exception, SystemExit):
                raised = ', raising %s' % ovf.outcome_name(result.exception)
            self.fail('%s: the import exits %d%s' % (name, result.exit_code, raised))
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


_add_appliance_tests(ApplianceCorpusTestCase)
