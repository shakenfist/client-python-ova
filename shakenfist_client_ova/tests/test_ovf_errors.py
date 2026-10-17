import testtools

from shakenfist_client_ova import ovf


def _subclasses():
    subclasses = set()
    pending = [ovf.OVFError]
    while pending:
        for subclass in pending.pop().__subclasses__():
            subclasses.add(subclass)
            pending.append(subclass)
    return subclasses


class ErrorClassesTestCase(testtools.TestCase):
    def test_every_error_says_when_it_is_raised(self):
        for error in _subclasses():
            self.assertTrue(error.__doc__ and error.__doc__.strip(), error.__name__)

    def test_every_error_is_exported(self):
        for error in _subclasses():
            self.assertIn(error.__name__, ovf.__all__)
            self.assertIs(error, getattr(ovf, error.__name__))


class MissingMemberErrorTestCase(testtools.TestCase):
    def test_one_member(self):
        e = ovf.MissingMemberError(['disk1.vmdk'])
        self.assertEqual(('disk1.vmdk',), e.members)
        self.assertEqual('References names a file the archive does not hold: "disk1.vmdk"', str(e))

    def test_several_members_in_the_order_given(self):
        e = ovf.MissingMemberError(('disk2.vmdk', 'disks/disk1.vmdk', 'cd.iso'))
        self.assertEqual(('disk2.vmdk', 'disks/disk1.vmdk', 'cd.iso'), e.members)
        self.assertEqual('References names 3 files the archive does not hold: "disk2.vmdk", "disks/disk1.vmdk", '
                         '"cd.iso"', str(e))

    def test_members_is_a_tuple_of_any_iterable(self):
        e = ovf.MissingMemberError(name for name in ['a.vmdk', 'b.vmdk'])
        self.assertEqual(('a.vmdk', 'b.vmdk'), e.members)

    def test_needs_a_member(self):
        self.assertRaises(ValueError, ovf.MissingMemberError, [])

    def test_is_an_ovf_error(self):
        e = ovf.MissingMemberError(['disk1.vmdk'])
        self.assertIsInstance(e, ovf.OVFError)
        self.assertEqual('MissingMemberError', ovf.outcome_name(e))
