"""The prose elements: vendor text that must never reach a committed file.

tools/trim-ovf-descriptor.py replaces their content in vendor fixtures, and
scrub() replaces the model fields they fill before a model from the upstream
corpus is written to an expected file.
"""


PLACEHOLDER = 'TRIMMED'

# The prose elements, as pairs of element path and the model field it fills.
# A path is matched against the tail of an element's ancestry, each segment
# being an element in an OVF envelope namespace. A model field is a path
# relative to VirtualSystem, with [] meaning each element of a list. None means
# that nothing in the model holds the element: Info and AnnotationSection are
# ignored unread, and Strings is not parsed. The trim tool uses only the
# element paths.
PROSE_ELEMENTS = (
    ('EulaSection/License', 'eulas[].license'),
    ('AnnotationSection/Annotation', None),
    ('ProductSection/Info', None),
    ('ProductSection/Product', 'products[].product'),
    ('ProductSection/Vendor', 'products[].vendor'),
    ('ProductSection/FullVersion', 'products[].full_version'),
    ('ProductSection/ProductUrl', 'products[].product_url'),
    ('ProductSection/VendorUrl', 'products[].vendor_url'),
    ('ProductSection/AppUrl', 'products[].app_url'),
    ('ProductSection/Category', 'products[].properties[].category'),
    ('ProductSection/Property/Label', 'products[].properties[].label'),
    ('ProductSection/Property/Description', 'products[].properties[].description'),
    ('VirtualSystem/Description', 'description'),
    ('VirtualSystemCollection/Description', 'description'),
    ('Strings/Msg', None),
)


def _scrub(obj, segments):
    name = segments[0]
    if name.endswith('[]'):
        for item in getattr(obj, name[:-2]):
            _scrub(item, segments[1:])
    elif len(segments) == 1:
        if getattr(obj, name):
            setattr(obj, name, PLACEHOLDER)
    else:
        child = getattr(obj, name)
        if child is not None:
            _scrub(child, segments[1:])


def scrub(virtual_system):
    """Replace every non-empty prose field of a VirtualSystem with PLACEHOLDER, in place.

    None and empty strings are left alone, as the trim tool leaves empty
    elements alone.
    """
    for _, path in PROSE_ELEMENTS:
        if path:
            _scrub(virtual_system, path.split('.'))
