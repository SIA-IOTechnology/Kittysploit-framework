#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""TLS helpers for KittySploit API and RPC servers."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Tuple
import ipaddress
import os
import shutil
import socket
import ssl
import subprocess


DEFAULT_TLS_DIR = Path.home() / ".kittysploit" / "tls"
DEFAULT_CERT_NAME = "kittysploit.crt"
DEFAULT_KEY_NAME = "kittysploit.key"


def default_tls_paths(output_dir: Optional[Path] = None) -> Tuple[Path, Path]:
    base = Path(output_dir or DEFAULT_TLS_DIR)
    return base / DEFAULT_CERT_NAME, base / DEFAULT_KEY_NAME


def resolve_tls_paths(
    cert: Optional[str] = None,
    key: Optional[str] = None,
) -> Tuple[Optional[Path], Optional[Path]]:
    """Resolve TLS file paths from CLI args or environment."""
    cert_value = (cert or os.environ.get("KITTYSPLOIT_SSL_CERT") or "").strip()
    key_value = (key or os.environ.get("KITTYSPLOIT_SSL_KEY") or "").strip()

    if not cert_value and not key_value:
        return None, None
    if bool(cert_value) != bool(key_value):
        raise ValueError(
            "SSL requires both --ssl-cert and --ssl-key "
            "(or KITTYSPLOIT_SSL_CERT / KITTYSPLOIT_SSL_KEY)."
        )

    return Path(cert_value).expanduser(), Path(key_value).expanduser()


def build_server_ssl_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    """Build a server-side SSL context from PEM certificate and key files."""
    cert_path = Path(cert_path).expanduser()
    key_path = Path(key_path).expanduser()
    if not cert_path.is_file():
        raise FileNotFoundError(f"SSL certificate not found: {cert_path}")
    if not key_path.is_file():
        raise FileNotFoundError(f"SSL private key not found: {key_path}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return context


def prepare_server_tls(
    *,
    ssl_enabled: bool = False,
    ssl_generate: bool = False,
    cert: Optional[str] = None,
    key: Optional[str] = None,
) -> Tuple[Optional[ssl.SSLContext], Optional[Path], Optional[Path]]:
    """Resolve or generate TLS material and return an SSL context if enabled."""
    if ssl_generate:
        ssl_enabled = True
    if not ssl_enabled:
        return None, None, None

    cert_path: Optional[Path]
    key_path: Optional[Path]

    if ssl_generate:
        cert_path, key_path = generate_self_signed_cert(force=True)
    else:
        cert_path, key_path = resolve_tls_paths(cert, key)
        if not cert_path or not key_path:
            cert_path, key_path = default_tls_paths()
            if not cert_path.is_file() or not key_path.is_file():
                raise ValueError(
                    "SSL enabled (--ssl) but no certificate found. "
                    "Use --ssl-generate or provide --ssl-cert / --ssl-key."
                )

    context = build_server_ssl_context(cert_path, key_path)
    return context, cert_path, key_path


def generate_self_signed_cert(
    output_dir: Optional[Path] = None,
    *,
    common_name: Optional[str] = None,
    days: int = 365,
    force: bool = False,
) -> Tuple[Path, Path]:
    """Generate a local self-signed TLS certificate (cryptography, else OpenSSL)."""
    output_dir = Path(output_dir or DEFAULT_TLS_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)
    cert_path, key_path = default_tls_paths(output_dir)

    if cert_path.is_file() and key_path.is_file() and not force:
        return cert_path, key_path

    cn = (common_name or socket.gethostname() or "localhost").strip() or "localhost"
    writers = (_generate_with_cryptography, _generate_with_openssl)
    errors = []
    for writer in writers:
        try:
            writer(cert_path=cert_path, key_path=key_path, common_name=cn, days=days)
            cert_path.chmod(0o644)
            key_path.chmod(0o600)
            return cert_path, key_path
        except Exception as exc:
            errors.append(f"{writer.__name__}: {exc}")

    raise RuntimeError("Unable to generate SSL certificate. " + " | ".join(errors))


def _generate_with_cryptography(
    *,
    cert_path: Path,
    key_path: Path,
    common_name: str,
    days: int,
) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    san_names = [
        x509.DNSName("localhost"),
        x509.DNSName(common_name),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    try:
        san_names.append(x509.IPAddress(ipaddress.IPv6Address("::1")))
    except Exception:
        pass

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=max(1, int(days))))
        .add_extension(x509.SubjectAlternativeName(san_names), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))


def _generate_with_openssl(
    *,
    cert_path: Path,
    key_path: Path,
    common_name: str,
    days: int,
) -> None:
    if shutil.which("openssl") is None:
        raise RuntimeError("openssl binary not found")

    command = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:4096",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
        "-days",
        str(max(1, int(days))),
        "-nodes",
        "-subj",
        f"/CN={common_name}",
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)


def service_scheme(ssl_context: Optional[ssl.SSLContext]) -> str:
    return "https" if ssl_context is not None else "http"
