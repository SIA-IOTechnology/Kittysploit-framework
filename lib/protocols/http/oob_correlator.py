#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Out-of-band interaction correlator (Interactsh-compatible + local HTTP fallback)."""

from __future__ import annotations

import base64
import json
import secrets
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    import requests
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    _CRYPTO_OK = True
except ImportError:
    _CRYPTO_OK = False
    requests = None  # type: ignore

_XID_ALPHABET = "0123456789abcdefghijklmnopqrstuv"
DEFAULT_INTERACTSH_SERVERS = (
    "oast.site",
    "oast.live",
    "oast.fun",
    "oast.online",
    "oast.pro",
    "oast.me",
)


@dataclass
class OobHit:
    token: str
    protocol: str
    remote_address: str = ""
    raw_request: str = ""
    full_id: str = ""


@dataclass
class _PendingCallback:
    token: str
    nonce: str
    full_host: str
    http_url: str
    created_at: float = field(default_factory=time.time)


class LocalHttpOobCorrelator:
    """Minimal HTTP callback collector (requires a reachable lhost for blind SSRF)."""

    def __init__(self, lhost: str, port: int = 0, path_prefix: str = "/ksp-oob"):
        self.lhost = lhost.strip()
        self.port = int(port or 0)
        self.path_prefix = path_prefix.rstrip("/")
        self._hits: Dict[str, OobHit] = {}
        self._lock = threading.Lock()
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._pending: Dict[str, _PendingCallback] = {}

    @property
    def enabled(self) -> bool:
        return bool(self.lhost)

    def start(self) -> bool:
        if not self.lhost:
            return False

        correlator = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args, **_kwargs):
                return

            def do_GET(self):
                token = ""
                path = self.path or "/"
                prefix = correlator.path_prefix + "/"
                if path.startswith(prefix):
                    token = path[len(prefix) :].split("/", 1)[0].strip()
                elif path.startswith("/"):
                    token = path.strip("/").split("/", 1)[0].strip()
                if token:
                    with correlator._lock:
                        correlator._hits[token] = OobHit(
                            token=token,
                            protocol="http",
                            remote_address=str(self.client_address[0]),
                            raw_request=f"GET {path}",
                            full_id=token,
                        )
                self.send_response(204)
                self.end_headers()

        try:
            self._httpd = ThreadingHTTPServer((self.lhost, self.port), Handler)
            self.port = int(self._httpd.server_address[1])
        except OSError:
            return False

        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        if self._httpd:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
            self._httpd = None

    def base_url(self) -> str:
        return f"http://{self.lhost}:{self.port}{self.path_prefix}"

    def issue_http(self, token: Optional[str] = None) -> Tuple[str, str]:
        token = token or secrets.token_hex(6)
        url = f"{self.base_url()}/{token}"
        self._pending[token] = _PendingCallback(
            token=token,
            nonce=token,
            full_host=self.lhost,
            http_url=url,
        )
        return token, url

    def poll(self) -> List[OobHit]:
        with self._lock:
            hits = list(self._hits.values())
            self._hits.clear()
        return hits

    def has_token(self, token: str) -> bool:
        with self._lock:
            return token in self._hits


class InteractshCorrelator:
    """ProjectDiscovery Interactsh client (register + poll + decrypt)."""

    def __init__(
        self,
        servers: Tuple[str, ...] = DEFAULT_INTERACTSH_SERVERS,
        correlation_length: int = 20,
        nonce_length: int = 13,
        timeout: float = 12.0,
        verify_ssl: bool = False,
    ):
        self.servers = servers
        self.correlation_length = max(8, int(correlation_length))
        self.nonce_length = max(4, int(nonce_length))
        self.timeout = float(timeout)
        self.verify_ssl = verify_ssl
        self.correlation_id = ""
        self.secret_key = ""
        self.server_host = ""
        self.server_base = ""
        self._private_key = None
        self._pending: Dict[str, _PendingCallback] = {}
        self._nonce_to_token: Dict[str, str] = {}
        self._hits: Dict[str, OobHit] = {}
        self._lock = threading.Lock()
        self._registered = False

    @property
    def enabled(self) -> bool:
        return self._registered

    @staticmethod
    def _random_xid_string(length: int) -> str:
        return "".join(secrets.choice(_XID_ALPHABET) for _ in range(length))

    def _encode_public_key_b64(self) -> str:
        assert self._private_key is not None
        pub_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return base64.standard_b64encode(pub_bytes).decode("ascii")

    def _decrypt_interaction_blob(self, aes_key_b64: str, ciphertext_b64: str) -> Optional[bytes]:
        assert self._private_key is not None
        try:
            enc_key = base64.standard_b64decode(aes_key_b64)
            key_plain = self._private_key.decrypt(
                enc_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
            )
            cipher_bytes = base64.standard_b64decode(ciphertext_b64)
            if len(cipher_bytes) < 16:
                return None
            iv, body = cipher_bytes[:16], cipher_bytes[16:]
            decryptor = Cipher(algorithms.AES(key_plain), modes.CTR(iv)).decryptor()
            return decryptor.update(body) + decryptor.finalize()
        except Exception:
            return None

    def register(self) -> bool:
        if not _CRYPTO_OK or requests is None:
            return False

        self.correlation_id = self._random_xid_string(self.correlation_length)
        self.secret_key = str(uuid.uuid4())
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        payload = {
            "public-key": self._encode_public_key_b64(),
            "secret-key": self.secret_key,
            "correlation-id": self.correlation_id,
        }
        body = json.dumps(payload).encode("utf-8")

        for server in self.servers:
            for scheme in ("https", "http"):
                base = f"{scheme}://{server.strip()}"
                try:
                    response = requests.post(
                        f"{base}/register",
                        data=body,
                        headers={"Content-Type": "application/json", "Accept": "application/json"},
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                    )
                except Exception:
                    continue
                if response.status_code != 200:
                    continue
                try:
                    data = response.json()
                except ValueError:
                    continue
                if str(data.get("message") or "").lower() != "registration successful":
                    continue
                self.server_base = base
                self.server_host = server.strip()
                self._registered = True
                return True
        return False

    def issue_http(self, token: Optional[str] = None) -> Tuple[str, str]:
        if not self._registered:
            raise RuntimeError("interactsh session not registered")
        token = token or secrets.token_hex(6)
        nonce = self._random_xid_string(self.nonce_length)
        full_host = f"{self.correlation_id}{nonce}.{self.server_host}"
        http_url = f"http://{full_host}/"
        pending = _PendingCallback(token=token, nonce=nonce, full_host=full_host, http_url=http_url)
        with self._lock:
            self._pending[token] = pending
            self._nonce_to_token[nonce] = token
        return token, http_url

    def issue_dns(self, token: Optional[str] = None) -> Tuple[str, str]:
        if not self._registered:
            raise RuntimeError("interactsh session not registered")
        token = token or secrets.token_hex(6)
        _, http_url = self.issue_http(token)
        host = http_url.split("://", 1)[-1].split("/", 1)[0]
        return token, host

    def _ingest_interaction(self, interaction: Dict[str, Any]):
        full_id = str(interaction.get("full-id") or interaction.get("full_id") or "")
        unique_id = str(interaction.get("unique-id") or interaction.get("unique_id") or "")
        protocol = str(interaction.get("protocol") or "http")
        remote = str(interaction.get("remote-address") or interaction.get("remote_address") or "")
        raw = str(interaction.get("raw-request") or interaction.get("raw_request") or "")

        token = ""
        with self._lock:
            for nonce, mapped in self._nonce_to_token.items():
                if nonce and (nonce in full_id or nonce in unique_id or nonce in raw):
                    token = mapped
                    break
            if not token:
                for pending in self._pending.values():
                    if pending.full_host in full_id or pending.nonce in full_id:
                        token = pending.token
                        break
        if not token:
            return
        with self._lock:
            self._hits[token] = OobHit(
                token=token,
                protocol=protocol,
                remote_address=remote,
                raw_request=raw[:4000],
                full_id=full_id or unique_id,
            )

    def poll_once(self) -> List[OobHit]:
        if not self._registered or not requests:
            return []
        url = f"{self.server_base}/poll?id={self.correlation_id}&secret={self.secret_key}"
        try:
            response = requests.get(url, timeout=self.timeout, verify=self.verify_ssl)
        except Exception:
            return []
        if response.status_code != 200:
            return []
        try:
            payload = response.json()
        except ValueError:
            return []

        aes_key = payload.get("aes_key") or payload.get("aesKey") or ""
        for blob in payload.get("data") or []:
            if not aes_key:
                continue
            plain = self._decrypt_interaction_blob(aes_key, blob)
            if not plain:
                continue
            try:
                interaction = json.loads(plain.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            if isinstance(interaction, dict):
                self._ingest_interaction(interaction)

        for extra in payload.get("extra") or []:
            try:
                interaction = json.loads(extra) if isinstance(extra, str) else extra
            except json.JSONDecodeError:
                continue
            if isinstance(interaction, dict):
                self._ingest_interaction(interaction)

        for entry in payload.get("tlddata") or payload.get("tldData") or []:
            if not entry:
                continue
            try:
                interaction = json.loads(entry) if isinstance(entry, str) else entry
            except json.JSONDecodeError:
                continue
            if isinstance(interaction, dict):
                self._ingest_interaction(interaction)

        with self._lock:
            hits = list(self._hits.values())
            self._hits.clear()
        return hits

    def wait_for(self, token: str, timeout: float = 10.0, interval: float = 1.5) -> Optional[OobHit]:
        deadline = time.monotonic() + max(0.5, timeout)
        while time.monotonic() < deadline:
            for hit in self.poll_once():
                if hit.token == token:
                    return hit
            with self._lock:
                cached = self._hits.get(token)
            if cached:
                return cached
            time.sleep(interval)
        return None

    def close(self):
        if not self._registered or not requests:
            return
        payload = json.dumps({"correlation-id": self.correlation_id, "secret-key": self.secret_key}).encode("utf-8")
        try:
            requests.post(
                f"{self.server_base}/deregister",
                data=payload,
                headers={"Content-Type": "application/json"},
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
        except Exception:
            pass
        self._registered = False


class OobCorrelator:
    """Facade: prefer Interactsh, optional local HTTP fallback."""

    def __init__(
        self,
        *,
        lhost: str = "",
        local_port: int = 0,
        interactsh_servers: Tuple[str, ...] = DEFAULT_INTERACTSH_SERVERS,
        prefer_interactsh: bool = True,
        timeout: float = 12.0,
    ):
        self.prefer_interactsh = prefer_interactsh
        self.timeout = timeout
        self.mode = ""
        self._interactsh = InteractshCorrelator(servers=interactsh_servers, timeout=timeout)
        self._local = LocalHttpOobCorrelator(lhost=lhost, port=local_port)
        self._backend: Any = None

    @property
    def enabled(self) -> bool:
        return self._backend is not None and getattr(self._backend, "enabled", False)

    def start(self) -> Tuple[bool, str]:
        if self.prefer_interactsh and _CRYPTO_OK and self._interactsh.register():
            self._backend = self._interactsh
            self.mode = "interactsh"
            return True, f"interactsh ({self._interactsh.server_host})"

        if self._local.lhost and self._local.start():
            self._backend = self._local
            self.mode = "local-http"
            return True, f"local HTTP ({self._local.lhost}:{self._local.port})"

        return False, ""

    def stop(self):
        if isinstance(self._backend, InteractshCorrelator):
            self._backend.close()
        elif isinstance(self._backend, LocalHttpOobCorrelator):
            self._backend.stop()
        self._backend = None
        self.mode = ""

    def issue_http(self, token: Optional[str] = None) -> Tuple[str, str]:
        if not self._backend:
            raise RuntimeError("OOB correlator not started")
        return self._backend.issue_http(token)

    def poll(self) -> List[OobHit]:
        if not self._backend:
            return []
        if hasattr(self._backend, "poll_once"):
            return self._backend.poll_once()
        return self._backend.poll()

    def wait_for(self, token: str, timeout: float = 8.0) -> Optional[OobHit]:
        if not self._backend:
            return None
        if hasattr(self._backend, "wait_for"):
            return self._backend.wait_for(token, timeout=timeout)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for hit in self.poll():
                if hit.token == token:
                    return hit
            time.sleep(1.2)
        return None


def guess_reachable_lhost() -> str:
    """Best-effort outbound interface IP (for lab/local SSRF callbacks)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except OSError:
        return "127.0.0.1"
