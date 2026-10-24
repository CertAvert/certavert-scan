"""Certificate details: turn the bytes a server sent into readable fields.

`describe()` is the main function: it takes a certificate in DER (the binary
form servers send) and returns a dict with its names, issuer, dates, days
left, key, signature, serial, SHA-256 fingerprint and the certificate itself
in PEM. That dict is what the JSON file holds under "certificate".

The reading is done by the `cryptography` package; the helpers below only
pick fields out and make them readable. Nothing here touches the network.
"""

from __future__ import annotations

import ipaddress
import math
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

# A certificate may list thousands of names; keep the first 200.
MAX_SANS = 200

# Elliptic curves by the names people know them by.
CURVES = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}


# ---------------------------------------------------------------------------
# Field helpers
# ---------------------------------------------------------------------------


def _utc(cert: x509.Certificate, field: str) -> datetime:
    """A certificate date in UTC. cryptography 42 added the *_utc properties and
    deprecated the naive ones; this works with both old and new versions."""
    value = getattr(cert, f"{field}_utc", None)
    if value is None:
        value = getattr(cert, field).replace(tzinfo=timezone.utc)
    return value


def _name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> Optional[str]:
    """One part of a name, such as the common name (CN) or organization (O)."""
    attrs = name.get_attributes_for_oid(oid)
    if not attrs:
        return None
    value = attrs[0].value
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _rfc4514(name: x509.Name) -> str:
    """The whole name as one line: "CN=intranet.local,O=Acme,C=US"."""
    try:
        return name.rfc4514_string()
    except Exception:  # an attribute cryptography can't print
        return ""


def _sans(cert: x509.Certificate) -> list[str]:
    """The names the certificate is valid for (Subject Alternative Names): DNS names and IPs."""
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except (x509.ExtensionNotFound, ValueError):
        return []
    names = [n.lower() for n in ext.value.get_values_for_type(x509.DNSName)]
    names += [str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress)]
    return list(dict.fromkeys(names))[:MAX_SANS]


def _key(cert: x509.Certificate) -> tuple[str, Optional[int]]:
    """The public key's type and size: ("RSA", 2048), ("EC P-256", 256)."""
    try:
        key = cert.public_key()
    except Exception:
        return "Unknown", None
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC {CURVES.get(key.curve.name, key.curve.name)}", key.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 456
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    return "Unknown", None


def _signature(cert: x509.Certificate) -> str:
    """How the issuer signed it: "sha256WithRSAEncryption", "ecdsa-with-SHA384"."""
    oid_name = getattr(cert.signature_algorithm_oid, "_name", None)
    if oid_name and oid_name != "Unknown OID":
        return oid_name
    return cert.signature_algorithm_oid.dotted_string


def _is_ca(cert: x509.Certificate) -> bool:
    """True for a CA certificate (one that signs others), which a server shouldn't send as its own."""
    try:
        return bool(cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca)
    except (x509.ExtensionNotFound, ValueError):
        return False


# ---------------------------------------------------------------------------
# Names and dates
# ---------------------------------------------------------------------------


def name_covers(pattern: str, name: str) -> bool:
    """Exact match, or a wildcard for exactly one leftmost label ("*.example.com")."""
    pattern, name = pattern.lower().rstrip("."), name.lower().rstrip(".")
    if pattern == name:
        return True
    if pattern.startswith("*.") and "." in name:
        return name.split(".", 1)[1] == pattern[2:] and pattern.count(".") >= 2
    return False


def covers(sans: list[str], common_name: Optional[str], name: str) -> bool:
    """True if a client connecting by `name` would accept this certificate's names."""
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        ip = None
    if ip is not None:
        return str(ip) in sans
    # Clients only look at the common name when there are no DNS names.
    candidates = sans if sans else ([common_name] if common_name else [])
    return any(name_covers(c, name) for c in candidates)


def days_left(not_after: datetime, now: datetime) -> int:
    """Whole days, rounded down, like CertAvert (negative once expired)."""
    return math.floor((not_after - now).total_seconds() / 86400)


# ---------------------------------------------------------------------------
# The whole certificate
# ---------------------------------------------------------------------------


def describe(der: bytes, now: Optional[datetime] = None) -> dict[str, Any]:
    """All the fields of one certificate. Raises ValueError if it can't be read."""
    now = now or datetime.now(timezone.utc)
    cert = x509.load_der_x509_certificate(der)
    not_before, not_after = _utc(cert, "not_valid_before"), _utc(cert, "not_valid_after")
    key_type, key_bits = _key(cert)
    return {
        "subject": _rfc4514(cert.subject),
        "common_name": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "organization": _name_attr(cert.subject, NameOID.ORGANIZATION_NAME),
        "sans": _sans(cert),
        "issuer": _rfc4514(cert.issuer),
        "issuer_common_name": _name_attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_organization": _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "self_signed": cert.issuer == cert.subject,
        "is_ca": _is_ca(cert),
        "not_before": not_before.isoformat().replace("+00:00", "Z"),
        "not_after": not_after.isoformat().replace("+00:00", "Z"),
        "days_left": days_left(not_after, now),
        "not_yet_valid": not_before > now,
        "serial": format(cert.serial_number, "X"),
        "sha256": cert.fingerprint(hashes.SHA256()).hex().upper(),
        "key_type": key_type,
        "key_bits": key_bits,
        "signature": _signature(cert),
        "pem": cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    }


def chain_pems(ders: list[bytes]) -> list[str]:
    """The other certificates the server sent (intermediates), in PEM; unreadable ones are skipped."""
    pems = []
    for der in ders:
        try:
            pems.append(x509.load_der_x509_certificate(der).public_bytes(serialization.Encoding.PEM).decode("ascii"))
        except ValueError:
            continue
    return pems
