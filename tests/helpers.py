"""Test certificates and a local TLS server."""

from __future__ import annotations

import os
import socket
import ssl
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def make_cert(
    common_name: str = "intranet.example.test",
    sans: Optional[list[str]] = None,
    days: int = 90,
    issuer_cn: Optional[str] = None,
) -> tuple[bytes, bytes]:
    """Return (certificate PEM, key PEM). Self-signed unless issuer_cn is given."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]) if issuer_cn else subject
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=max(1, -days + 30)))
        .not_valid_after(now + timedelta(days=days, hours=1))
    )
    names = sans if sans is not None else [common_name]
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    cert = builder.sign(key, hashes.SHA256())
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


def der_of(pem: bytes) -> bytes:
    return x509.load_pem_x509_certificate(pem).public_bytes(serialization.Encoding.DER)


class TLSServer:
    """Accepts connections on 127.0.0.1 and does a TLS handshake with the given certificate."""

    def __init__(self, cert_pem: bytes, key_pem: bytes) -> None:
        self.dir = tempfile.mkdtemp()
        cert_path, key_path = os.path.join(self.dir, "c.pem"), os.path.join(self.dir, "k.pem")
        with open(cert_path, "wb") as f:
            f.write(cert_pem)
        with open(key_path, "wb") as f:
            f.write(key_pem)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(cert_path, key_path)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.settimeout(2)
                with self.ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1)
            except (ssl.SSLError, OSError):
                pass

    def close(self) -> None:
        self.running = False
        self.thread.join(2)
        self.sock.close()


class PlainServer:
    """An open port that is not TLS: answers with a banner and closes."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                conn.sendall(b"SSH-2.0-OpenSSH_9.0\r\n")
            except OSError:
                pass
            conn.close()

    def close(self) -> None:
        self.running = False
        self.thread.join(2)
        self.sock.close()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
