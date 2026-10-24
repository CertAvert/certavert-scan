import unittest
from datetime import datetime, timedelta, timezone

from certavert_scan import certinfo, probe
from tests.helpers import der_of, make_cert


class DescribeTest(unittest.TestCase):
    def test_fields(self):
        pem, _ = make_cert("app.example.test", sans=["app.example.test", "*.app.example.test"], days=45, issuer_cn="Acme Internal CA")
        c = certinfo.describe(der_of(pem))
        self.assertEqual(c["common_name"], "app.example.test")
        self.assertEqual(c["sans"], ["app.example.test", "*.app.example.test"])
        self.assertEqual(c["issuer_common_name"], "Acme Internal CA")
        self.assertFalse(c["self_signed"])
        self.assertEqual(c["days_left"], 45)
        self.assertEqual((c["key_type"], c["key_bits"]), ("EC P-256", 256))
        self.assertEqual(len(c["sha256"]), 64)
        self.assertTrue(c["pem"].startswith("-----BEGIN CERTIFICATE-----"))
        self.assertTrue(c["not_after"].endswith("Z"))

    def test_days_left_rounds_down(self):
        now = datetime(2026, 10, 1, tzinfo=timezone.utc)
        self.assertEqual(certinfo.days_left(now + timedelta(days=3, hours=23), now), 3)
        self.assertEqual(certinfo.days_left(now - timedelta(hours=1), now), -1)

    def test_status(self):
        for days, expected in ((90, "OK"), (31, "OK"), (30, "Expiring"), (0, "Expiring")):
            pem, _ = make_cert(days=days)
            with self.subTest(days=days):
                self.assertEqual(probe.status(certinfo.describe(der_of(pem)), 30), expected)
        pem, _ = make_cert(days=-3)
        self.assertEqual(probe.status(certinfo.describe(der_of(pem)), 30), "Expired")


class NameTest(unittest.TestCase):
    def test_name_covers(self):
        self.assertTrue(certinfo.name_covers("a.example.test", "A.example.test"))
        self.assertTrue(certinfo.name_covers("*.example.test", "a.example.test"))
        self.assertFalse(certinfo.name_covers("*.example.test", "a.b.example.test"))
        self.assertFalse(certinfo.name_covers("*.example.test", "example.test"))
        self.assertFalse(certinfo.name_covers("*.test", "example.test"))

    def test_covers_falls_back_to_common_name_only_without_sans(self):
        self.assertTrue(certinfo.covers([], "old.example.test", "old.example.test"))
        self.assertFalse(certinfo.covers(["new.example.test"], "old.example.test", "old.example.test"))

    def test_issues(self):
        pem, _ = make_cert("a.example.test")
        c = certinfo.describe(der_of(pem))
        self.assertEqual(probe.issues(c, "b.example.test", "TLSv1.1"), ["Self-signed", "Name not in certificate", "Old protocol (TLSv1.1)"])
        self.assertEqual(probe.issues(c, None, "TLSv1.3"), ["Self-signed"])


if __name__ == "__main__":
    unittest.main()
