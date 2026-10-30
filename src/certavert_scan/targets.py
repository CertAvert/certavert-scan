"""Targets: turn what the user typed into a list of endpoints to connect to.

A *target* is what the user writes on the command line or in the settings
file: a network ("10.0.0.0/24"), an address ("10.0.0.5", "fd00::5") or a host
name ("intranet.example.local"), each with an optional port ("…:8443").

An *endpoint* is one address and one port the scanner will connect to.
`expand()` turns targets into endpoints: every address of a network times
every port, minus the excluded addresses, each endpoint once.

Nothing here touches the network except `resolve()`, which asks DNS for a
host name's address.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterable, Iterator, Optional, Union


# Ports where the server speaks TLS from the first byte (no STARTTLS):
# 443 HTTPS, 465 SMTPS, 636 LDAPS, 990 FTPS, 993 IMAPS, 995 POP3S,
# 5986 WinRM over HTTPS, 8443 and 9443 the usual alternative HTTPS ports.
DEFAULT_PORTS = (443, 465, 636, 990, 993, 995, 5986, 8443, 9443)

# A /16. Bigger scans are refused unless the user raises the limit, so a typo
# like 10.0.0.0/8 (16 million addresses) doesn't start a day-long scan.
DEFAULT_MAX_ADDRESSES = 65536

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class TargetError(ValueError):
    """A target, port or exclude the user wrote can't be understood. The message says which."""


@dataclass(frozen=True)
class Endpoint:
    """One address and port to connect to."""

    address: str  # the IP connected to
    port: int
    name: Optional[str] = None  # sent as SNI and compared with the certificate
    report_closed: bool = False  # the port was asked for ("host:8443"): say so when it's closed

    @property
    def label(self) -> str:
        """How the endpoint is shown: "intranet.local:443", "10.0.0.5:443", "[fd00::5]:443"."""
        host = self.name or self.address
        if ":" in host:
            host = f"[{host}]"
        return f"{host}:{self.port}"


@dataclass(frozen=True)
class Target:
    """One target as written: a network, an address or a name, with an optional port."""

    network: Optional[Network] = None
    name: Optional[str] = None
    port: Optional[int] = None

    def size(self) -> int:
        """How many addresses this target stands for (without network and broadcast addresses)."""
        if self.network is None:
            return 1
        if self.network.num_addresses <= 2:
            return self.network.num_addresses
        return self.network.num_addresses - 2 if self.network.version == 4 else self.network.num_addresses - 1


def parse_ports(text: str) -> tuple[int, ...]:
    """Parse "443,8443,9000-9010" into (443, 8443, 9000, …, 9010), each port once, in order."""
    ports: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, _, high = part.partition("-")
            first, last = _port(low), _port(high)
            if first > last:
                raise TargetError(f"bad port range: {part}")
            ports.extend(range(first, last + 1))
        else:
            ports.append(_port(part))
    if not ports:
        raise TargetError("no ports given")
    return tuple(dict.fromkeys(ports))


def _port(text: str) -> int:
    """One port number, 1 to 65535."""
    try:
        port = int(text.strip())
    except ValueError:
        raise TargetError(f"bad port: {text!r}") from None
    if not 1 <= port <= 65535:
        raise TargetError(f"port out of range: {port}")
    return port


def parse_target(text: str) -> Target:
    """Parse "10.0.0.0/24", "10.0.0.5", "10.0.0.5:8443", "[fd00::1]:443", "intranet.local:8443"."""
    text = text.strip()
    if not text:
        raise TargetError("empty target")
    # People paste addresses from the browser: keep only the host and port.
    if "://" in text:
        text = text.split("://", 1)[1].split("/", 1)[0]

    # Split off the port. IPv6 addresses contain colons themselves, so a port
    # after one needs brackets: "[fd00::1]:443". A bare "fd00::1" has no port.
    port: Optional[int] = None
    host = text
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            raise TargetError(f"bad target: {text}")
        host, rest = text[1:end], text[end + 1 :]
        if rest:
            if not rest.startswith(":"):
                raise TargetError(f"bad target: {text}")
            port = _port(rest[1:])
    elif text.count(":") == 1:
        host, _, port_text = text.partition(":")
        port = _port(port_text)

    # A network, an address, or else a host name.
    if "/" in host:
        try:
            network = ipaddress.ip_network(host, strict=False)
        except ValueError:
            raise TargetError(f"bad network: {host}") from None
        return Target(network=network, port=port)

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return Target(network=ipaddress.ip_network(address), port=port)

    name = host.rstrip(".").lower()
    if not name or len(name) > 253 or any(not label or len(label) > 63 for label in name.split(".")):
        raise TargetError(f"bad host name: {host}")
    return Target(name=name, port=port)


def read_targets_file(path: str) -> list[str]:
    """Targets from a text file (--file): any number per line, "#" starts a comment."""
    lines = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if line:
                lines.extend(line.split())
    return lines


def parse_excludes(items: Iterable[str]) -> list[Network]:
    """Excludes as networks. Each item may hold several, comma-separated ("10.0.0.1,10.0.5.0/28")."""
    networks = []
    for item in items:
        for part in item.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                networks.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                raise TargetError(f"bad exclude (use an address or a network): {part}") from None
    return networks


def is_excluded(address: str, excludes: list[Network]) -> bool:
    """True if the address is in one of the excluded networks."""
    ip = ipaddress.ip_address(address)
    return any(ip.version == net.version and ip in net for net in excludes)


def resolve(name: str) -> Optional[str]:
    """A host name's address from DNS (IPv4 preferred), or None if it has none."""
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return None
    for family in (socket.AF_INET, socket.AF_INET6):
        for info in infos:
            if info[0] == family:
                return info[4][0]
    return None


def _addresses(network: Network) -> Iterator[str]:
    """Every usable address of a network, one at a time (a /16 is never held in memory)."""
    if network.num_addresses == 1:
        yield str(network.network_address)
    else:
        for ip in network.hosts():
            yield str(ip)


def endpoint_count(targets: list[Target], ports: tuple[int, ...]) -> int:
    """How many endpoints `expand()` will give at most, for the progress line."""
    return sum(t.size() * (1 if t.port else len(ports)) for t in targets)


def expand(
    targets: list[Target],
    ports: tuple[int, ...],
    excludes: list[Network],
    unresolved: list[str],
) -> Iterator[Endpoint]:
    """Yield every endpoint once. Names that don't resolve are added to `unresolved`.

    Overlaps are found against the networks already done (not a set of every
    endpoint, which would hold ~600,000 entries for a /16).
    """
    named: set[tuple[str, int, str]] = set()
    done: list[tuple[Network, frozenset[int]]] = []

    def already(address: str, port: int) -> bool:
        ip = ipaddress.ip_address(address)
        return any(ip.version == net.version and port in done_ports and ip in net for net, done_ports in done)

    # Targets with a port first, so "host host:8443" keeps 8443 as asked for.
    for target in sorted(targets, key=lambda t: t.port is None):
        target_ports = (target.port,) if target.port else ports

        # A host name: look up its address once, connect to that address and
        # send the name (SNI) so the server picks the right certificate.
        if target.name is not None:
            address = resolve(target.name)
            if address is None:
                unresolved.append(target.name)
                continue
            if is_excluded(address, excludes):
                continue
            for port in target_ports:
                key = (address, port, target.name)
                if key not in named:
                    named.add(key)
                    yield Endpoint(address, port, target.name, report_closed=target.port is not None)
            continue

        # A network or a single address: every address times every port.
        assert target.network is not None
        report_closed = target.port is not None and target.network.num_addresses == 1
        for address in _addresses(target.network):
            if is_excluded(address, excludes):
                continue
            for port in target_ports:
                if not already(address, port):
                    yield Endpoint(address, port, None, report_closed)
        done.append((target.network, frozenset(target_ports)))
