"""Allocation units, parsed as DSP0004's programmatic units of bytes.

A descriptor gives a disk's capacity and a memory item's quantity in a unit
such as "byte * 2^20". DSP0004, the CIM Infrastructure specification, defines
these programmatic units: a base unit followed by multipliers, each joined by "*".
The parser reads only units whose base is a byte, because only those convert
to a byte count:

* spaces may appear around every token;
* the base is "byte", in any case;
* each multiplier is 2^N or 10^N, with N a non-negative integer, or a positive
  integer.

The names KiloBytes, MegaBytes and GigaBytes, which some producers write
instead, are read as powers of two. Anything else, including a unit with
another base such as "hertz * 10^6", is refused.
"""

import re

from .errors import UnknownAllocationUnitError


# The names some producers write in place of a programmatic unit, in lower
# case. Each is a power of two, as producers mean them.
LEGACY_UNITS = {
    'kilobytes': 2 ** 10,
    'megabytes': 2 ** 20,
    'gigabytes': 2 ** 30,
}

_POWER_RE = re.compile(r'\s*(2|10)\s*\^\s*([0-9]{1,3})\s*')
_INTEGER_RE = re.compile(r'\s*([0-9]{1,40})\s*')

# No real unit comes near this. Refusing a larger factor, and limiting each
# number's digits in the expressions above, bounds the arithmetic done on a
# descriptor's text.
MAX_FACTOR = 2 ** 128


def _refuse(text):
    return UnknownAllocationUnitError(
        'Unknown allocation unit "%s": only a byte count, such as "byte * 2^20", is understood' % text)


def bytes_per_unit(text):
    """The number of bytes in one of the allocation unit text names, as an int.

    Raises UnknownAllocationUnitError, naming the text, for a unit that is not
    a byte count: another base, a malformed or negative multiplier, or an empty
    string.
    """
    legacy = LEGACY_UNITS.get(text.strip().lower())
    if legacy is not None:
        return legacy

    terms = text.split('*')
    if terms[0].strip().lower() != 'byte':
        raise _refuse(text)

    factor = 1
    for term in terms[1:]:
        power = _POWER_RE.fullmatch(term)
        integer = _INTEGER_RE.fullmatch(term)
        if power:
            factor *= int(power.group(1)) ** int(power.group(2))
        elif integer and int(integer.group(1)) > 0:
            factor *= int(integer.group(1))
        else:
            raise _refuse(text)
        if factor > MAX_FACTOR:
            raise _refuse(text)
    return factor
