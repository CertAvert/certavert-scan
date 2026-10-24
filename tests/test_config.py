import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest import mock

try:
    import tomllib
except ImportError:
    import tomli as tomllib

from certavert_scan import cli, config
from tests.helpers import TLSServer, make_cert
from tests.test_scan import isolated, read_json


def write(folder, text, name=config.FILE_NAME):
    path = os.path.join(folder, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path


def run(*args, stdin_tty=False, answer="n"):
    with redirect_stderr(io.StringIO()) as err, mock.patch("sys.stdin.isatty", return_value=stdin_tty), mock.patch("builtins.input", return_value=answer):
        code = cli.main(list(args))
    return code, err.getvalue()


class LoadTest(unittest.TestCase):
    def test_defaults_fill_what_the_file_leaves_out(self):
        folder = tempfile.mkdtemp()
        settings = config.load(write(folder, 'targets = ["10.0.0.0/24"]\nworkers = 8\noutput = "~/scans"\n'))
        self.assertEqual(settings["targets"], ["10.0.0.0/24"])
        self.assertEqual(settings["workers"], 8)
        self.assertEqual(settings["ports"], config.DEFAULTS["ports"])
        self.assertEqual(settings["output"], os.path.expanduser("~/scans"))

    def test_unknown_setting_suggests_the_right_one(self):
        folder = tempfile.mkdtemp()
        with self.assertRaisesRegex(config.ConfigError, "unknown setting 'exlude' \\(did you mean exclude\\?\\)"):
            config.load(write(folder, "exlude = []\n"))

    def test_wrong_types(self):
        folder = tempfile.mkdtemp()
        for text, message in (
            ('workers = "8"', "workers must be a whole number"),
            ("workers = true", "workers must be a whole number"),
            ('targets = "10.0.0.0/24"', "targets must be a list"),
            ("ports = [443, true]", "ports must be numbers"),
            ("reverse_dns = 1", "reverse_dns must be true or false"),
        ):
            with self.subTest(text=text), self.assertRaisesRegex(config.ConfigError, message):
                config.load(write(folder, text + "\n"))

    def test_bad_toml(self):
        with self.assertRaisesRegex(config.ConfigError, config.FILE_NAME):
            config.load(write(tempfile.mkdtemp(), "targets = [\n"))


class TemplateTest(unittest.TestCase):
    def test_reads_back_with_the_network_and_output(self):
        data = tomllib.loads(config.template(["192.168.1.0/24"], "C:\\Users\\jane\\scans"))
        self.assertEqual(data["targets"], ["192.168.1.0/24"])
        self.assertEqual(data["output"], "C:\\Users\\jane\\scans")
        self.assertEqual(data["ports"], list(config.DEFAULTS["ports"]))
        self.assertEqual(set(data) - set(config.TYPES), set())

    def test_without_a_network(self):
        data = tomllib.loads(config.template([], "/home/jane"))
        self.assertEqual(data["targets"], [])

    def test_never_overwrites(self):
        path = write(tempfile.mkdtemp(), "workers = 4\n")
        with self.assertRaises(FileExistsError):
            config.write_template(path, [], "/tmp")

    def test_local_networks_are_private_slash_24s(self):
        for network in config.local_networks():
            self.assertTrue(network.endswith("/24"))


class CliConfigTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = TLSServer(*make_cert("ok.example.test", days=200))

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def settings(self, folder, extra=""):
        out = os.path.join(folder, "out")
        return write(folder, f'targets = ["127.0.0.1"]\nports = [{self.server.port}]\noutput = "{out}"\nreverse_dns = false\n{extra}'), out

    def test_settings_file_in_the_current_folder_is_used(self):
        with isolated() as folder:
            _, out = self.settings(folder)
            code, err = run("--name", "scan", "--format", "json")
            self.assertEqual(code, 0, err)
            doc = read_json(out)
        self.assertEqual(doc["endpoints"][0]["certificate"]["common_name"], "ok.example.test")
        self.assertEqual(doc["scan"]["targets"], ["127.0.0.1"])

    def test_command_line_wins_over_the_file(self):
        with isolated() as folder:
            self.settings(folder, 'formats = ["html"]\n')
            other = os.path.join(folder, "other")
            code, err = run("127.0.0.1:1", "-o", other, "--name", "scan", "--format", "json")
            self.assertEqual(code, 0, err)
            doc = read_json(other)
        self.assertEqual(doc["scan"]["targets"], ["127.0.0.1:1"])
        self.assertEqual(doc["endpoints"][0]["error"], "Port closed or not reachable")

    def test_excludes_add_to_the_file(self):
        with isolated() as folder:
            _, out = self.settings(folder, 'exclude = ["10.9.9.9"]\n')
            code, err = run("-x", "127.0.0.1", "--name", "scan", "--format", "json")
            self.assertEqual(code, 0, err)
            doc = read_json(out)
        self.assertEqual(doc["scan"]["excluded"], ["10.9.9.9/32", "127.0.0.1/32"])
        self.assertEqual(doc["endpoints"], [])

    def test_bad_setting_stops_with_the_file_name(self):
        with isolated() as folder:
            write(folder, "workerz = 4\n")
            code, err = run()
        self.assertEqual(code, 2)
        self.assertIn("did you mean workers", err)

    def test_no_config_ignores_the_file(self):
        with isolated() as folder:
            write(folder, "workerz = 4\n")
            code, err = run("--no-config", "127.0.0.1:1", "-o", folder, "--format", "json")
        self.assertEqual(code, 0, err)

    def test_init_writes_and_never_overwrites(self):
        with isolated() as folder, mock.patch.object(config, "local_networks", return_value=["192.168.7.0/24"]):
            code, _ = run("--init")
            self.assertEqual(code, 0)
            with open(os.path.join(folder, config.FILE_NAME), "rb") as handle:
                data = tomllib.load(handle)
            self.assertEqual(data["targets"], ["192.168.7.0/24"])
            self.assertEqual(os.path.realpath(data["output"]), os.path.realpath(folder))
            code, err = run("--init")
        self.assertEqual(code, 2)
        self.assertIn("already exists", err)


class FirstRunTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = TLSServer(*make_cert("first.example.test", days=200))

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def test_writes_the_user_file_and_asks_before_scanning(self):
        with isolated() as folder, mock.patch.object(config, "local_networks", return_value=["192.168.7.0/24"]):
            code, err = run(stdin_tty=True, answer="n")
            path = config.user_config_path()
            self.assertTrue(path.startswith(folder))
            self.assertTrue(os.path.isfile(path))
            self.assertEqual(os.listdir(folder), ["config"])  # nothing scanned, no results
        self.assertEqual(code, 0)
        self.assertIn("192.168.7.0/24", err)
        self.assertIn("Change the file if you need to", err)

    def test_without_a_terminal_it_never_scans_unasked(self):
        with isolated() as folder, mock.patch.object(config, "local_networks", return_value=["192.168.7.0/24"]):
            code, err = run(stdin_tty=False)
            self.assertEqual(os.listdir(folder), ["config"])
        self.assertEqual(code, 0)
        self.assertIn("--yes", err)

    def test_yes_scans_at_once_and_the_next_run_uses_the_file(self):
        network = "127.0.0.1/32"
        with isolated() as folder, mock.patch.object(config, "local_networks", return_value=[network]), mock.patch.object(config.targets, "DEFAULT_PORTS", (self.server.port,)):
            code, err = run("--yes", "--name", "first", "--format", "json", "--no-reverse-dns")
            self.assertEqual(code, 0, err)
            doc = read_json_named(folder, "first")
            self.assertEqual(doc["endpoints"][0]["certificate"]["common_name"], "first.example.test")
            code, err = run("--name", "second", "--format", "json", "--no-reverse-dns")
            self.assertEqual(code, 0, err)
            self.assertNotIn("First run", err)
            self.assertEqual(read_json_named(folder, "second")["scan"]["targets"], [network])

    def test_no_network_found(self):
        with isolated(), mock.patch.object(config, "local_networks", return_value=[]):
            code, err = run(stdin_tty=True, answer="y")
        self.assertEqual(code, 0)
        self.assertIn("No private network found", err)


def read_json_named(folder, name):
    with open(os.path.join(folder, f"{name}.json"), encoding="utf-8") as handle:
        return json.load(handle)


if __name__ == "__main__":
    unittest.main()
