"""The manifest parser.

A manifest is UTF-8 text with one entry per line, ALGORITHM(name)= digest,
which producers space in more than one way:

    SHA256(disk1.vmdk)= e1a654d69cf4112756899c6d63...       (ovftool)
    SHA1 (myvm-disk001.vmdk) = aeb6a6c54fcc579d7a13...      (VirtualBox)

Spaces are allowed before the opening bracket and either side of the equals
sign. The algorithm is SHA1, SHA256 or SHA512, in any case, and is kept in
lower case. SHA512 is not in OVF 2.x's list, but ovftool writes it when asked.
The digest is hexadecimal of the algorithm's length, in either case; it is
kept as written, so a comparison with a computed digest must ignore case.

A carriage return before a line's newline is ignored, so a manifest with
CRLF line endings parses. Blank lines are skipped, and the last line needs no
newline. Each name may have only one entry. A line that breaks any of these
rules is a ManifestError, whose message gives its line number, and so is a
manifest that is not UTF-8.
"""

import re

from .errors import ManifestError, OVFError
from .model import Manifest, ManifestEntry


# The algorithm stops at the first space or opening bracket, so that a name
# may hold brackets of its own; the name runs to the last ")=" on the line.
MANIFEST_LINE_RE = re.compile(r'^([^ (]+) *\((.+)\) *= *(.*)$')

# The length of each algorithm's digest in hexadecimal digits, by its name in lower case.
DIGEST_LENGTHS = {
    'sha1': 40,
    'sha256': 64,
    'sha512': 128,
}

HEX_RE = re.compile(r'[0-9A-Fa-f]+')


def _lines(text):
    """Each line of text with its number, less its newline and a carriage return before that."""
    lines = text.split('\n')
    for number, line in enumerate(lines, start=1):
        if number < len(lines) and line.endswith('\r'):
            line = line[:-1]
        yield number, line


def _parse_manifest(data):
    manifest = Manifest()
    first_lines = {}
    for number, line in _lines(data.decode()):
        if not line:
            continue

        m = MANIFEST_LINE_RE.match(line)
        if not m:
            raise ManifestError('Manifest line %d is "%s", which is not ALGORITHM(name)= digest' % (number, line))
        algorithm, name, digest = m.groups()

        length = DIGEST_LENGTHS.get(algorithm.lower())
        if length is None:
            raise ManifestError('Manifest line %d uses the algorithm "%s", which is not SHA1, SHA256 or SHA512'
                                % (number, algorithm))
        if len(digest) != length or not HEX_RE.fullmatch(digest):
            raise ManifestError('Manifest line %d gives "%s" the %s digest "%s", which is not %d hexadecimal digits'
                                % (number, name, algorithm, digest, length))
        if name in first_lines:
            raise ManifestError('Manifest line %d repeats "%s", already given by line %d'
                                % (number, name, first_lines[name]))
        first_lines[name] = number

        manifest.entries.append(ManifestEntry(name=name, algorithm=algorithm.lower(), digest=digest))
    return manifest


def parse_manifest(data):
    """Parse a manifest's bytes into a Manifest, keeping its entries in order.

    Raises ManifestError for a line that breaks the rules above, and for any
    other failure, such as a manifest that is not UTF-8, in which case it is
    raised from the original exception.
    """
    try:
        return _parse_manifest(data)
    except OVFError:
        raise
    except Exception as e:
        raise ManifestError(
            'Could not parse the manifest: %s: %s' % (type(e).__name__, e)) from e
