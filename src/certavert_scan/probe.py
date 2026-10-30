"""Probe: connect to one endpoint, do a TLS handshake and read what the server sends.

This is the only part of the tool that talks to other machines. For each
endpoint it:

1. opens a TCP connection (a closed port ends here),
2. does a TLS handshake, sending the host name (SNI) when there is one,
3. keeps the server's certificate, the TLS version and the cipher,
4. closes the connection. No request is sent, nothing is logged in to.

Certificate verification is off on purpose: internal CAs, self-signed and
expired certificates are exactly what the tool is for, so it reads them all
and reports what it finds (`status()` and `issues()` below) instead of
refusing the connection.
"""

from __future__ import annotations

import errno
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Optional

from certavert_scan import certinfo
from certavert_scan.targets import Endpoint

# Protocol versions reported as "Old protocol" (browsers dropped them in 2020).
OLD_TLS = {"SSLv3", "TLSv1", "TLSv1.1"}


def _context() -> ssl.SSLContext:
    """A TLS client that accepts any certificate and the oldest protocols Python allows."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Read old servers too (TLS 1.0, small keys): this tool reports them, it doesn't trust them.
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, OSError):
        pass
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    return ctx


def _peer_chain(sock: ssl.SSLSocket) -> list[bytes]:
    """Every certificate the server sent (its own first), in DER.

    Only Python 3.13 and newer can give this without verifying; older versions
    return an empty list and the results have the server's own certificate only.
    """
    getter = getattr(sock, "get_unverified_chain", None)
    if getter is None:
        return []
    try:
        chain = getter() or []
    except Exception:
        return []
    out = []
    for item in chain:
        if isinstance(item, (bytes, bytearray)):
            out.append(bytes(item))
        elif hasattr(item, "public_bytes"):
            try:
                out.append(item.public_bytes(ssl._ssl.ENCODING_DER))  # type: ignore[attr-defined]
            except Exception:
                pass
    return out


def _closed(error: OSError) -> bool:
    """True when the error means "nothing listens there": refused, unreachable or timed out."""
    return isinstance(error, (ConnectionRefusedError, socket.timeout, TimeoutError)) or error.errno in (
        errno.ECONNREFUSED,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        errno.ETIMEDOUT,
        errno.EHOSTDOWN,
    )


def _reverse_dns(address: str) -> Optional[str]:
    """The name DNS gives for an address (PTR record), to make results from a range readable."""
    try:
        return socket.gethostbyaddr(address)[0].lower()
    except (OSError, UnicodeError):
        return None


def probe(
    endpoint: Endpoint,
    timeout: float,
    expiring_days: int,
    reverse_dns: bool = False,
    now: Optional[datetime] = None,
) -> Optional[dict[str, Any]]:
    """Probe one endpoint and return its result (a dict, written as-is to the JSON file).

    Returns None for a closed port nobody asked for by number: scanning a /24 on
    9 ports would otherwise list ~2,000 closed ports.
    """
    now = now or datetime.now(timezone.utc)
    # Every result has every key, so the JSON file always has the same shape.
    result: dict[str, Any] = {
        "endpoint": endpoint.label,
        "address": endpoint.address,
        "port": endpoint.port,
        "name": endpoint.name,
        "reverse_dns": None,
        "status": "Error",
        "error": None,
        "tls_version": None,
        "cipher": None,
        "issues": [],
        "certificate": None,
        "chain": [],
    }

    # Step 1: TCP connection.
    try:
        raw = socket.create_connection((endpoint.address, endpoint.port), timeout=timeout)
    except OSError as error:
        if not endpoint.report_closed and _closed(error):
            return None
        result["error"] = "Port closed or not reachable" if _closed(error) else f"Connection failed: {error}"
        return result

    # Step 2 and 3: TLS handshake, then read the certificate. Leaving the
    # `with` block closes the TLS connection (step 4).
    try:
        raw.settimeout(timeout)
        with _context().wrap_socket(raw, server_hostname=endpoint.name or None) as tls:
            der = tls.getpeercert(binary_form=True)
            result["tls_version"] = tls.version()
            cipher = tls.cipher()
            result["cipher"] = cipher[0] if cipher else None
            chain = _peer_chain(tls)
    except (ssl.SSLError, OSError) as error:
        result["error"] = "Not TLS, or the TLS handshake failed" + (
            f" ({error.reason})" if isinstance(error, ssl.SSLError) and getattr(error, "reason", None) else ""
        )
        if isinstance(error, (socket.timeout, TimeoutError)):
            result["error"] = "Port open, no TLS answer (timed out)"
        return result
    finally:
        try:
            raw.close()
        except OSError:
            pass

    # Only for endpoints that answered, so a /16 doesn't mean 65,000 DNS lookups.
    if reverse_dns and not endpoint.name:
        result["reverse_dns"] = _reverse_dns(endpoint.address)

    # Read the certificate's details.
    if not der:
        result["error"] = "The server sent no certificate"
        return result
    try:
        cert = certinfo.describe(der, now)
    except ValueError as error:
        result["error"] = f"Certificate could not be read ({error})"
        return result

    result["certificate"] = cert
    # The server's own certificate is the first in the chain: keep only the rest.
    result["chain"] = certinfo.chain_pems(chain[1:]) if chain and chain[0] == der else certinfo.chain_pems(chain)
    result["error"] = None
    result["status"] = status(cert, expiring_days)
    result["issues"] = issues(cert, endpoint.name, result["tls_version"])
    return result


def status(cert: dict[str, Any], expiring_days: int) -> str:
    """The certificate's status from its dates alone: Expired, Not yet valid, Expiring or OK."""
    if cert["days_left"] < 0:
        return "Expired"
    if cert["not_yet_valid"]:
        return "Not yet valid"
    if cert["days_left"] <= expiring_days:
        return "Expiring"
    return "OK"


def issues(cert: dict[str, Any], name: Optional[str], tls_version: Optional[str]) -> list[str]:
    """Problems besides the dates, as short labels for the Issues column.

    These don't change the status: an internal certificate is often
    self-signed on purpose, and the status should still say when it expires.
    """
    found = []
    if cert["self_signed"]:
        found.append("Self-signed")
    if name and not certinfo.covers(cert["sans"], cert["common_name"], name):
        found.append("Name not in certificate")
    if tls_version in OLD_TLS:
        found.append(f"Old protocol ({tls_version})")
    signature = (cert["signature"] or "").lower()
    if "sha1" in signature or "md5" in signature:
        found.append("Weak signature")
    if cert["key_type"] == "RSA" and (cert["key_bits"] or 0) < 2048:
        found.append(f"Small key (RSA {cert['key_bits']})")
    return found
