import csv
import io
import json
import os
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr
from unittest import mock

from certavert_scan import cli, output, probe
from certavert_scan.targets import Endpoint
from tests.helpers import PlainServer, TLSServer, free_port, make_cert


@contextmanager
def isolated():
    """A temporary current folder and settings folder, so no real settings file is read."""
    folder, cwd = tempfile.mkdtemp(), os.getcwd()
    os.chdir(folder)
    try:
        with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": os.path.join(folder, "config"), "APPDATA": os.path.join(folder, "config")}):
            yield folder
    finally:
        os.chdir(cwd)


def read_text(folder, name, encoding="utf-8"):
    with open(os.path.join(folder, name), encoding=encoding) as handle:
        return handle.read()


def read_json(folder):
    return json.loads(read_text(folder, "scan.json"))


def read_csv(folder):
    return list(csv.reader(io.StringIO(read_text(folder, "scan.csv", "utf-8-sig"))))


class ProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tls = TLSServer(*make_cert("intranet.example.test", days=20, issuer_cn="Acme Internal CA"))
        cls.plain = PlainServer()

    @classmethod
    def tearDownClass(cls):
        cls.tls.close()
        cls.plain.close()

    def test_reads_the_certificate(self):
        r = probe.probe(Endpoint("127.0.0.1", self.tls.port, "intranet.example.test"), 3, 30)
        self.assertEqual(r["status"], "Expiring")
        self.assertIsNone(r["error"])
        self.assertEqual(r["certificate"]["common_name"], "intranet.example.test")
        self.assertEqual(r["certificate"]["days_left"], 20)
        self.assertIn(r["tls_version"], ("TLSv1.2", "TLSv1.3"))
        self.assertEqual(r["issues"], [])
        self.assertEqual(r["endpoint"], f"intranet.example.test:{self.tls.port}")

    def test_wrong_name(self):
        r = probe.probe(Endpoint("127.0.0.1", self.tls.port, "other.example.test"), 3, 30)
        self.assertEqual(r["issues"], ["Name not in certificate"])

    def test_not_tls(self):
        r = probe.probe(Endpoint("127.0.0.1", self.plain.port), 3, 30)
        self.assertEqual(r["status"], "Error")
        self.assertIn("TLS", r["error"])
        self.assertIsNone(r["certificate"])

    def test_closed_port_is_left_out_unless_asked_for(self):
        port = free_port()
        self.assertIsNone(probe.probe(Endpoint("127.0.0.1", port), 1, 30))
        r = probe.probe(Endpoint("127.0.0.1", port, report_closed=True), 1, 30)
        self.assertEqual(r["error"], "Port closed or not reachable")


class CliTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = [
            TLSServer(*make_cert("ok.example.test", days=200)),
            TLSServer(*make_cert("<script>alert(1)</script>", sans=[], days=-2)),
        ]

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.close()

    def run_cli(self, *args):
        out = tempfile.mkdtemp()
        with isolated(), redirect_stderr(io.StringIO()) as err:
            code = cli.main([*args, "-o", out, "--name", "scan", "--no-reverse-dns", "-t", "2"])
        return code, out, err.getvalue()

    def test_writes_the_three_files(self):
        ports = ",".join(str(s.port) for s in self.servers) + f",{free_port()}"
        code, out, err = self.run_cli("127.0.0.0/30", "-p", ports)
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(os.listdir(out)), ["scan.csv", "scan.html", "scan.json"])

        doc = read_json(out)
        self.assertEqual((doc["format"], doc["format_version"]), ("certavert-scan", 1))
        # The servers listen on 127.0.0.1 only: 127.0.0.2 and the closed port are left out.
        statuses = [e["status"] for e in doc["endpoints"]]
        self.assertEqual(statuses, ["Expired", "OK"])
        self.assertEqual(doc["summary"]["certificates"], 2)
        self.assertEqual(doc["summary"]["Expired"], 1)

        rows = read_csv(out)
        self.assertEqual(rows[0], output.CSV_COLUMNS)
        self.assertEqual(len(rows), 3)

        page = read_text(out, "scan.html")
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("certavert.com", page)
        self.assertIn("Found 2 endpoints, 2 certificates: 1 expired, 1 ok", err)

    def test_named_target_with_unknown_name(self):
        code, out, _ = self.run_cli("does-not-exist.invalid:443", "--format", "json")
        self.assertEqual(code, 0)
        doc = read_json(out)
        self.assertEqual(doc["endpoints"][0]["error"], "Name not found in DNS")

    def test_refuses_too_many_addresses(self):
        code, _, err = self.run_cli("10.0.0.0/8")
        self.assertEqual(code, 2)
        self.assertIn("--max-addresses", err)

    def test_bad_target(self):
        code, _, err = self.run_cli("10.0.0.0/40")
        self.assertEqual(code, 2)
        self.assertIn("bad network", err)

    def test_csv_cells_are_not_formulas(self):
        self.assertEqual(output._cell("=HYPERLINK(1)"), "'=HYPERLINK(1)")
        self.assertEqual(output._cell(-2), "'-2")


if __name__ == "__main__":
    unittest.main()
