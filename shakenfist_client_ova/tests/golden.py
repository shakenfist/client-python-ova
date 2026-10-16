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
"""

import json
import os
import re

from shakenfist_client_ova import ovf


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


def outcome(descriptor_path):
    """Parse a descriptor, returning (to_json text, None) or (None, the OVFError)."""
    with open(descriptor_path, 'rb') as f:
        data = f.read()
    try:
        return ovf.to_json(ovf.parse_descriptor(data)), None
    except ovf.OVFError as e:
        return None, e


def _read(path):
    try:
        with open(path, 'rb') as f:
            return f.read().decode('utf-8')
    except FileNotFoundError:
        return None


def _write(path, text):
    # Binary, with \n endings: the fixtures are marked -text, so git never converts these.
    with open(path, 'wb') as f:
        f.write(text.encode('utf-8'))


def _old_fragment(text):
    try:
        old = json.loads(text)
    except (TypeError, ValueError):
        return None
    if isinstance(old, dict):
        return old.get('message_contains')
    return None


def update(descriptor_path):
    """Rewrite a descriptor's expected file from the parser's current behaviour."""
    path = expected_path(descriptor_path)
    model_text, exc = outcome(descriptor_path)
    if exc is None:
        _write(path, model_text)
        return

    fragment = _old_fragment(_read(path))
    if not isinstance(fragment, str) or not fragment or fragment not in str(exc):
        fragment = PLACEHOLDER
    _write(path, dump({'error': ovf.outcome_name(exc), 'message_contains': fragment}))


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
    expected_text = _read(path)
    if expected_text is None:
        testcase.fail('%s has no expected file; run with %s=1 to create %s' % (
            name, UPDATE_VARIABLE, os.path.basename(path)))

    model_text, exc = outcome(descriptor_path)
    expected = json.loads(expected_text)
    expects_error = isinstance(expected, dict) and set(expected) == {'error', 'message_contains'}

    if exc is None:
        if expects_error:
            testcase.fail('%s parsed, but %s expects %s' % (name, os.path.basename(path), expected['error']))
        testcase.assertEqual(expected_text, model_text, '%s: the parsed model differs from its expected file' % name)
        return

    if not expects_error:
        testcase.fail('%s raised %s: %s, but its expected file holds a model' % (name, ovf.outcome_name(exc), exc))
    testcase.assertEqual(expected['error'], ovf.outcome_name(exc), '%s: the wrong outcome' % name)
    testcase.assertNotEqual(PLACEHOLDER, expected['message_contains'], '%s: choose a message_contains fragment' % name)
    testcase.assertIn(expected['message_contains'], str(exc), '%s: the message no longer holds the fragment' % name)
