#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Persistent implant identity — Ed25519 keypair per build.

* implant_id = first 16 hex chars of SHA-256(public key)
* relay_token / client_id defaults to implant_id
* hello line: KSID:<implant_id>:<base64url(signature)>
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

HELLO_MAGIC = "KSID"
_ID_RE = re.compile(r"^[a-f0-9]{16}$")


@dataclass
class ImplantIdentity:
    implant_id: str
    private_key_pem: str
    public_key_pem: str

    @property
    def relay_token(self) -> str:
        return self.implant_id

    def sign(self, message: bytes) -> bytes:
        key = serialization.load_pem_private_key(self.private_key_pem.encode(), password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise TypeError("expected Ed25519 private key")
        return key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        key = serialization.load_pem_public_key(self.public_key_pem.encode())
        if not isinstance(key, ed25519.Ed25519PublicKey):
            return False
        try:
            key.verify(signature, message)
            return True
        except Exception:
            return False


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def implant_id_from_public_pem(public_key_pem: str) -> str:
    key = serialization.load_pem_public_key(public_key_pem.encode())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise TypeError("expected Ed25519 public key")
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def generate_implant_identity() -> ImplantIdentity:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    iid = implant_id_from_public_pem(public_pem)
    return ImplantIdentity(implant_id=iid, private_key_pem=private_pem, public_key_pem=public_pem)


def save_implant_identity(identity: ImplantIdentity, directory: str | Path = "output/implant_keys") -> Path:
    root = Path(directory)
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{identity.implant_id}.json"
    path.write_text(
        json.dumps(
            {
                "implant_id": identity.implant_id,
                "private_key_pem": identity.private_key_pem,
                "public_key_pem": identity.public_key_pem,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return path


def load_implant_identity(path: str | Path) -> ImplantIdentity:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return ImplantIdentity(
        implant_id=str(data["implant_id"]),
        private_key_pem=str(data["private_key_pem"]),
        public_key_pem=str(data["public_key_pem"]),
    )


def build_identity_hello(identity: ImplantIdentity) -> bytes:
    """Signed hello banner sent after transport connect."""
    msg = identity.implant_id.encode("utf-8")
    sig = identity.sign(msg)
    line = f"{HELLO_MAGIC}:{identity.implant_id}:{_b64url(sig)}\n"
    return line.encode("utf-8")


def parse_identity_hello(line: str) -> Tuple[str, bytes]:
    parts = line.strip().split(":", 2)
    if len(parts) != 3 or parts[0] != HELLO_MAGIC:
        raise ValueError("invalid identity hello")
    implant_id = parts[1].strip()
    if not _ID_RE.match(implant_id):
        raise ValueError("invalid implant_id")
    return implant_id, _b64url_decode(parts[2])


def verify_identity_hello(line: str, public_key_pem: str) -> str:
    """Verify hello line; return implant_id on success."""
    implant_id, signature = parse_identity_hello(line)
    key = serialization.load_pem_public_key(public_key_pem.encode())
    if not isinstance(key, ed25519.Ed25519PublicKey):
        raise ValueError("invalid public key")
    expected = implant_id_from_public_pem(public_key_pem)
    if implant_id != expected:
        raise ValueError("implant_id mismatch")
    key.verify(signature, implant_id.encode("utf-8"))
    return implant_id


def embedded_private_key_block(private_key_pem: str) -> str:
    """Compact PEM literal for generated Python implants."""
    return repr(private_key_pem.strip())


def embedded_sign_hello_code(private_key_pem: str) -> str:
    """Python snippet: send KSID hello on socket ``s``."""
    pem_lit = embedded_private_key_block(private_key_pem)
    return (
        "from cryptography.hazmat.primitives import serialization\n"
        "from cryptography.hazmat.primitives.asymmetric import ed25519\n"
        "import base64,hashlib\n"
        f"_pem={pem_lit}\n"
        "_pk=serialization.load_pem_private_key(_pem.encode(),password=None)\n"
        "_pub=_pk.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()\n"
        "_raw=_pk.public_key().public_bytes(encoding=serialization.Encoding.Raw,format=serialization.PublicFormat.Raw)\n"
        "_iid=__import__('hashlib').sha256(_raw).hexdigest()[:16]\n"
        "_sig=_pk.sign(_iid.encode())\n"
        "_b=base64.urlsafe_b64encode(_sig).decode().rstrip('=')\n"
        "s.sendall(f'KSID:{_iid}:{_b}\\n'.encode())\n"
        "_iid\n"
    )
