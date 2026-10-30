r"""Settings file: where it lives, reading it, and writing the first one.

The settings file is `certavert-scan.toml`, in TOML (a simple "name = value"
format). It is looked for in the current folder first, then in the user's
settings folder:

- macOS, Linux: ~/.config/certavert-scan/certavert-scan.toml
- Windows:      %APPDATA%\certavert-scan\certavert-scan.toml

On the first run (no file and no targets) `template()` writes one with this
machine's network (`local_networks()`), the default ports and the current
folder for the results. Its comments explain every setting.
"""

from __future__ import annotations

import difflib
import ipaddress
import os
import socket
import sys
from typing import Any, Optional

try:
    import tomllib
except ImportError:  # Python 3.9 and 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from certavert_scan import targets

FILE_NAME = "certavert-scan.toml"


# Used for anything the file doesn't set.
DEFAULTS: dict[str, Any] = {
    "targets": [],
    "exclude": [],
    "ports": list(targets.DEFAULT_PORTS),
    "output": None,  # the current folder, or the home folder when that can't be written to
    "formats": ["html", "csv", "json"],
    "workers": 32,
    "timeout": 3.0,
    "expiring_days": 30,
    "reverse_dns": True,
    "max_addresses": targets.DEFAULT_MAX_ADDRESSES,
}

# What each setting must be. Anything not listed here is refused, so a typo
# ("exlude") stops the run instead of being silently ignored.
TYPES: dict[str, tuple] = {
    "targets": (list,),
    "exclude": (list,),
    "ports": (list,),
    "output": (str,),
    "formats": (list,),
    "workers": (int,),
    "timeout": (int, float),
    "expiring_days": (int,),
    "reverse_dns": (bool,),
    "max_addresses": (int,),
}

# How the error message describes each type.
TYPE_NAMES = {
    "targets": "a list",
    "exclude": "a list",
    "ports": "a list",
    "output": "text (a folder)",
    "formats": "a list",
    "workers": "a whole number",
    "timeout": "a number of seconds",
    "expiring_days": "a whole number",
    "reverse_dns": "true or false",
    "max_addresses": "a whole number",
}


class ConfigError(ValueError):
    """The settings file can't be read or has a wrong setting. The message names the file."""


def user_config_path() -> str:
    """The user's own settings file, whether it exists or not."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "certavert-scan", FILE_NAME)


def find() -> Optional[str]:
    """The file in the current folder first, then the user's own."""
    for path in (os.path.join(os.getcwd(), FILE_NAME), user_config_path()):
        if os.path.isfile(path):
            return path
    return None


def load(path: str) -> dict[str, Any]:
    """Read and check a settings file; return every setting (defaults for the rest)."""
    try:
        with open(path, "rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"{path}: {error}") from None
    except OSError as error:
        raise ConfigError(f"{path}: {error.strerror or error}") from None

    for key, value in data.items():
        if key not in TYPES:
            close = difflib.get_close_matches(key, TYPES, n=1)
            hint = f" (did you mean {close[0]}?)" if close else ""
            raise ConfigError(f"{path}: unknown setting {key!r}{hint}")
        expected = TYPES[key]
        # bool is an int in Python: don't accept `workers = true`.
        if not isinstance(value, expected) or (isinstance(value, bool) and bool not in expected):
            raise ConfigError(f"{path}: {key} must be {TYPE_NAMES[key]}")
        if key in ("targets", "exclude", "formats") and not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{path}: {key} must be a list of text")
        if key == "ports" and not all(isinstance(v, (int, str)) and not isinstance(v, bool) for v in value):
            raise ConfigError(f"{path}: ports must be numbers or ranges like \"9000-9010\"")

    settings = dict(DEFAULTS)
    settings.update(data)
    if settings["output"]:
        settings["output"] = os.path.expanduser(settings["output"])
    return settings


def default_output() -> str:
    """Where results go when nothing says: the current folder, or home if it's read-only."""
    cwd = os.getcwd()
    return cwd if os.access(cwd, os.W_OK) else os.path.expanduser("~")


def local_networks() -> list[str]:
    """The /24 around this machine's private IPv4 address, if it has one.

    Asks the operating system which address it would use to reach the
    internet (a UDP "connect" sends no packet), so it works the same on
    Windows, macOS and Linux. The real netmask isn't portable to read;
    a /24 is the common office size and the file says to change it.
    """
    found = []
    for probe_address in ("192.0.2.1", "10.255.255.255", "8.8.8.8"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((probe_address, 9))
                address = sock.getsockname()[0]
        except OSError:
            continue
        ip = ipaddress.ip_address(address)
        if ip.is_private and not ip.is_loopback and not ip.is_link_local:
            network = str(ipaddress.ip_network(f"{address}/24", strict=False))
            if network not in found:
                found.append(network)
        break
    return found


def _toml_string(text: str) -> str:
    """Text as a TOML value."""
    # Literal strings ('...') keep Windows backslashes as they are.
    if "'" not in text and "\n" not in text:
        return f"'{text}'"
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def template(networks: list[str], output: str) -> str:
    """The first settings file, with a comment above each setting."""
    if networks:
        target_lines = "\n".join(f"  {_toml_string(n)}," for n in networks)
        found = f"# Found from this machine's address: {', '.join(networks)}. Change it if your\n# network is bigger (10.0.0.0/16) or add more networks, addresses and names.\n#\n"
    else:
        target_lines = "  # '192.168.1.0/24',"
        found = "# No private network found on this machine: add yours below.\n#\n"
    ports = ", ".join(str(p) for p in targets.DEFAULT_PORTS)
    return f"""# certavert-scan settings. Run `certavert-scan` to scan with them.
# Anything given on the command line wins over this file.
# Only scan networks you own or are allowed to scan.

{found}# Networks (10.0.0.0/24), addresses (10.0.0.5) and host names
# (intranet.example.local), each with an optional port (mail.example.local:993).
# Names are better than addresses where you have them: a server with several
# sites sends the right certificate only when asked by name.
targets = [
{target_lines}
]

# Addresses or networks never to connect to (printers, factory or medical devices).
exclude = []

# Ports for targets without one. Numbers or ranges ("9000-9010").
ports = [{ports}]

# Folder for the results.
output = {_toml_string(output)}

# Files to write: html, csv, json.
formats = ["html", "csv", "json"]

# Connections at the same time, and seconds to wait at each step.
workers = 32
timeout = 3

# Days left counted as Expiring.
expiring_days = 30

# Look up names for addresses that answer.
reverse_dns = true
"""


def write_template(path: str, networks: list[str], output: str) -> None:
    """Write the first settings file (and its folder). Never overwrites an existing one."""
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)
    # "x": never overwrite a file someone has edited.
    with open(path, "x", encoding="utf-8", newline="\n") as handle:
        handle.write(template(networks, output))
