import ipaddress
import unittest

from certavert_scan import targets
from certavert_scan.targets import TargetError, parse_target


class ParseTargetTest(unittest.TestCase):
    def test_network(self):
        t = parse_target("10.0.0.0/24")
        self.assertEqual(t.network, ipaddress.ip_network("10.0.0.0/24"))
        self.assertIsNone(t.port)
        self.assertEqual(t.size(), 254)

    def test_network_not_on_boundary(self):
        self.assertEqual(parse_target("10.0.0.7/30").network, ipaddress.ip_network("10.0.0.4/30"))

    def test_address_with_port(self):
        t = parse_target("10.0.0.5:8443")
        self.assertEqual(t.network, ipaddress.ip_network("10.0.0.5/32"))
        self.assertEqual(t.port, 8443)
        self.assertEqual(t.size(), 1)

    def test_ipv6(self):
        self.assertEqual(parse_target("fd00::1").network, ipaddress.ip_network("fd00::1/128"))
        t = parse_target("[fd00::1]:8443")
        self.assertEqual((t.network, t.port), (ipaddress.ip_network("fd00::1/128"), 8443))

    def test_name(self):
        t = parse_target("Intranet.Example.Local.:636")
        self.assertEqual((t.name, t.port), ("intranet.example.local", 636))

    def test_url_is_accepted(self):
        t = parse_target("https://intranet.example.local:8443/login")
        self.assertEqual((t.name, t.port), ("intranet.example.local", 8443))

    def test_bad(self):
        for text in ("", "10.0.0.0/33", "host:0", "host:70000", "host:abc", "[fd00::1", "a..b"):
            with self.subTest(text=text), self.assertRaises(TargetError):
                parse_target(text)


class PortsTest(unittest.TestCase):
    def test_list_and_range(self):
        self.assertEqual(targets.parse_ports("443, 8443,9000-9002,443"), (443, 8443, 9000, 9001, 9002))

    def test_bad(self):
        for text in ("", "0", "9002-9000", "x"):
            with self.subTest(text=text), self.assertRaises(TargetError):
                targets.parse_ports(text)


class ExpandTest(unittest.TestCase):
    def expand(self, items, ports=(443,), excludes=()):
        unresolved = []
        parsed = [parse_target(i) for i in items]
        out = list(targets.expand(parsed, ports, targets.parse_excludes(excludes), unresolved))
        return out, unresolved

    def test_range_uses_ports_and_skips_network_and_broadcast(self):
        out, _ = self.expand(["10.0.0.0/30"], ports=(443, 8443))
        self.assertEqual([(e.address, e.port) for e in out], [("10.0.0.1", 443), ("10.0.0.1", 8443), ("10.0.0.2", 443), ("10.0.0.2", 8443)])
        self.assertFalse(any(e.report_closed for e in out))

    def test_closed_is_reported_only_for_a_port_asked_for(self):
        out, _ = self.expand(["10.0.0.9", "10.0.0.10:8443", "localhost", "localhost:8443"])
        asked = {(e.name or e.address, e.port): e.report_closed for e in out}
        self.assertEqual(asked, {("10.0.0.9", 443): False, ("10.0.0.10", 8443): True, ("localhost", 443): False, ("localhost", 8443): True})

    def test_a_port_asked_for_wins_over_the_same_port_from_the_defaults(self):
        out, _ = self.expand(["localhost", "localhost:443", "10.0.0.0/30", "10.0.0.1:443"])
        asked = {(e.name or e.address, e.port): e.report_closed for e in out}
        self.assertEqual(len(out), 3)
        self.assertTrue(asked[("localhost", 443)])
        self.assertTrue(asked[("10.0.0.1", 443)])
        self.assertFalse(asked[("10.0.0.2", 443)])

    def test_overlaps_are_scanned_once(self):
        out, _ = self.expand(["10.0.0.0/29", "10.0.0.0/30", "10.0.0.2"])
        self.assertEqual(sorted(e.address for e in out), ["10.0.0.%d" % i for i in range(1, 7)])

    def test_other_port_is_not_an_overlap(self):
        out, _ = self.expand(["10.0.0.0/30", "10.0.0.1:8443"])
        self.assertIn(("10.0.0.1", 8443), [(e.address, e.port) for e in out])

    def test_excludes(self):
        out, _ = self.expand(["10.0.0.0/29"], excludes=["10.0.0.1,10.0.0.4/31"])
        self.assertEqual([e.address for e in out], ["10.0.0.2", "10.0.0.3", "10.0.0.6"])

    def test_name_resolves_and_keeps_sni(self):
        out, unresolved = self.expand(["localhost:8443"])
        self.assertEqual(unresolved, [])
        self.assertEqual((out[0].name, out[0].port), ("localhost", 8443))
        self.assertIn(out[0].address, ("127.0.0.1", "::1"))
        self.assertEqual(out[0].label, "localhost:8443")

    def test_unresolved(self):
        out, unresolved = self.expand(["does-not-exist.invalid"])
        self.assertEqual((out, unresolved), ([], ["does-not-exist.invalid"]))

    def test_endpoint_count(self):
        parsed = [parse_target("10.0.0.0/24"), parse_target("10.0.1.1:8443")]
        self.assertEqual(targets.endpoint_count(parsed, (443, 636)), 254 * 2 + 1)


if __name__ == "__main__":
    unittest.main()
