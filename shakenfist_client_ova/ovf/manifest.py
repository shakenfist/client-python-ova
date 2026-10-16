"""The manifest parser.

This is the import command's manifest loop, moved here from the
command without changing what it accepts. The parser will later read the manifest
by the rules in docs/plans/PLAN-ovf-parser.md; until then it is as the command had it.
"""

import re

from .errors import ManifestError, OVFError
from .model import Manifest, ManifestEntry


# Manifest files contain either sha1 or sha256 hashes
#     SHA1 (myvm-disk001.vmdk) = aeb6a6c54fcc579d7a130b5f70faf98b4eab9c07
#     SHA256(disk1.vmdk)= e1a654d69cf4112756899c6d639...c760e2f271146cbf5
MANIFEST_LINE_RE = re.compile(r'^([^ ]+) *\((.*)\) *= *(.*)$')


def _parse_manifest(data):
    manifest = Manifest()
    for line in data.decode().split('\n'):
        if not line:
            continue

        m = MANIFEST_LINE_RE.match(line)
        if m:
            alg = m.group(1).lower()
            filename = m.group(2)
            hash = m.group(3)
            manifest.entries.append(ManifestEntry(name=filename, algorithm=alg, digest=hash))
        else:
            raise ManifestError(f'Failed to parse manifest line: {line}')
    return manifest


def parse_manifest(data):
    """Parse a manifest's bytes into a Manifest, keeping every line in order.

    Raises ManifestError for a line that does not parse, and for any other
    failure, such as a manifest that is not UTF-8, in which case it is raised
    from the original exception.
    """
    try:
        return _parse_manifest(data)
    except OVFError:
        raise
    except Exception as e:
        raise ManifestError(
            'Could not parse the manifest: %s: %s' % (type(e).__name__, e)) from e
