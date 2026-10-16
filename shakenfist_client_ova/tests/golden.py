"""Helpers for comparing the parser's outcome on a descriptor with an expected file.

Every descriptor has an expected file beside it, named for the descriptor with
".ovf" replaced by ".expected.json". The expected file holds one of two things:

* For a descriptor that parses, exactly ovf.to_json of the Envelope.
* For one that does not, {"error": <ovf.outcome_name of the exception>,
  "message_contains": <a fragment the exception's message must contain>}. The
  fragment is chosen by a person, as a phrase that will survive rewording of
  the rest of the message.

Setting OVF_UPDATE_EXPECTED=1 rewrites the expected files from the parser's
current behaviour. A run in that mode never passes, so that it cannot be left
switched on in CI: the rewritten files are reviewed with git diff, and the tests
are run again without the variable.

The corpus tests in shakenfist_client_ova/corpus_tests keep many such values in
one JSON object keyed by descriptor. They share expected_entry and problem with
the per-descriptor files, so both kinds of expected value mean the same thing.
"""

import difflib
import json
import os
import re

from shakenfist_client_ova import ovf
from shakenfist_client_ova.ovf import prose


FIXTURE_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures', 'ovf')
UPDATE_VARIABLE = 'OVF_UPDATE_EXPECTED'

# Written into an expected file when its old fragment no longer matches. It is
# never a substring of a message, so the test fails until a person replaces it.
PLACEHOLDER = 'CHOOSE A STABLE FRAGMENT'


def update_mode():
    return os.environ.get(UPDATE_VARIABLE, '') not in ('', '0')


def expected_path(descriptor_path):
    return descriptor_path[:-len('.ovf')] + '.expected.json'


def _walk(root, suffix):
    found = []
    for directory, _, names in os.walk(root):
        for name in names:
            if name.endswith(suffix):
                found.append(os.path.join(directory, name))
    return sorted(found)


def descriptor_paths(root=FIXTURE_ROOT):
    """Every .ovf file under root, sorted."""
    return [p for p in _walk(root, '.ovf')]


def expected_paths(root=FIXTURE_ROOT):
    """Every .expected.json file under root, sorted."""
    return _walk(root, '.expected.json')


def test_name(descriptor_path, root=FIXTURE_ROOT):
    """A method name for a descriptor, such as test_vendor_wazuh_4_9_1."""
    relative = os.path.relpath(descriptor_path, root)[:-len('.ovf')]
    return 'test_' + re.sub(r'[^0-9a-z]+', '_', relative.lower()).strip('_')


def dump(value):
    """Serialise a dict as to_json does, so that every expected file looks alike."""
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + '\n'


def outcome_of(data, scrub=False):
    """Parse descriptor bytes, returning (to_json text, None) or (None, the OVFError).

    With scrub, the model's prose fields are replaced first. The upstream corpora
    use it, so that no vendor text reaches a committed file.
    """
    try:
        envelope = ovf.parse_descriptor(data)
        if scrub:
            prose.scrub(envelope.virtual_system)
        return ovf.to_json(envelope), None
    except ovf.OVFError as e:
        return None, e


def outcome(descriptor_path, scrub=False):
    """Parse a descriptor file, returning (to_json text, None) or (None, the OVFError)."""
    with open(descriptor_path, 'rb') as f:
        return outcome_of(f.read(), scrub)


def read(path):
    """The text of a file, or None if it does not exist."""
    try:
        with open(path, 'rb') as f:
            return f.read().decode('utf-8')
    except FileNotFoundError:
        return None


def write(path, text):
    """Write text as UTF-8 with LF endings, which git never converts: the fixtures are marked -text."""
    with open(path, 'wb') as f:
        f.write(text.encode('utf-8'))


def is_error_entry(expected):
    return isinstance(expected, dict) and set(expected) == {'error', 'message_contains'}


def expected_entry(model_text, exc, old=None):
    """What an expected value should hold for an outcome.

    That is the parsed model, or an error entry. old is the previous parsed
    value, if there was one: its message_contains is kept while the exception's
    message still holds it, else PLACEHOLDER is written for a person to replace.
    """
    if exc is None:
        return json.loads(model_text)
    fragment = old.get('message_contains') if isinstance(old, dict) else None
    if not isinstance(fragment, str) or not fragment or fragment not in str(exc):
        fragment = PLACEHOLDER
    return {'error': ovf.outcome_name(exc), 'message_contains': fragment}


def problem(name, expected, model_text, exc):
    """Describe how an outcome differs from a parsed expected value, or return None if it matches."""
    expects_error = is_error_entry(expected)

    if exc is None:
        if expects_error:
            return '%s parsed, but its expected value is %s' % (name, expected['error'])
        actual = json.loads(model_text)
        if actual == expected:
            return None
        diff = list(difflib.unified_diff(
            dump(expected).splitlines(), dump(actual).splitlines(), 'expected', 'parsed', lineterm='', n=1))
        if len(diff) > 30:
            diff = diff[:30] + ['...']
        return '%s: the parsed model differs from its expected value:\n%s' % (name, '\n'.join(diff))

    if not expects_error:
        return '%s raised %s: %s, but its expected value holds a model' % (name, ovf.outcome_name(exc), exc)
    if expected['error'] != ovf.outcome_name(exc):
        return '%s: the wrong outcome: expected %s, got %s: %s' % (
            name, expected['error'], ovf.outcome_name(exc), exc)
    if expected['message_contains'] == PLACEHOLDER:
        return '%s: choose a message_contains fragment' % name
    if expected['message_contains'] not in str(exc):
        return '%s: the message no longer holds the fragment %r: %s' % (name, expected['message_contains'], exc)
    return None


def update(descriptor_path):
    """Rewrite a descriptor's expected file from the parser's current behaviour."""
    path = expected_path(descriptor_path)
    model_text, exc = outcome(descriptor_path)
    if exc is None:
        write(path, model_text)
        return

    try:
        old = json.loads(read(path))
    except (TypeError, ValueError):
        old = None
    write(path, dump(expected_entry(model_text, exc, old)))


def check(testcase, descriptor_path):
    """Fail testcase unless the parser's outcome on descriptor_path is the expected one.

    In update mode this rewrites the expected file and then always fails.
    """
    name = os.path.relpath(descriptor_path, FIXTURE_ROOT)
    if update_mode():
        update(descriptor_path)
        testcase.fail(
            '%s=1: rewrote the expected file for %s. Review git diff, choose any "%s" fragment, and run '
            'again without the variable.' % (UPDATE_VARIABLE, name, PLACEHOLDER))

    path = expected_path(descriptor_path)
    expected_text = read(path)
    if expected_text is None:
        testcase.fail('%s has no expected file; run with %s=1 to create %s' % (
            name, UPDATE_VARIABLE, os.path.basename(path)))

    model_text, exc = outcome(descriptor_path)
    expected = json.loads(expected_text)
    if exc is None and not is_error_entry(expected):
        # A model must match byte for byte, so that the file stays exactly to_json's output.
        testcase.assertEqual(expected_text, model_text, '%s: the parsed model differs from its expected file' % name)
    message = problem(name, expected, model_text, exc)
    if message:
        testcase.fail(message)
