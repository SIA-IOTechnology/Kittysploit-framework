#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WPS enrollee M2 builder (PIN mode, simplified KDF for KittySploit stack)."""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization

from lib.protocols.wlan.wsc import (
    WSC_OUI,
    WscMessage,
    _ATTR_AUTHENTICATOR,
    _ATTR_DEV_PASSWORD_ID,
    _ATTR_ENROLLEE_NONCE,
    _ATTR_MSG_TYPE,
    _ATTR_PUBLIC_KEY,
    _ATTR_REGISTRAR_NONCE,
    _ATTR_VERSION,
    LLC_SNAP_EAPOL,
)

_PIN_ATTR_ID = 0x1020
_ENC_SETTINGS_ATTR = 0x101E


def _kdf(key: bytes, label: bytes) -> bytes:
    return hmac.new(key, label, hashlib.sha256).digest()


def _build_attr(attr_id: int, value: bytes) -> bytes:
    return struct.pack(">HH", attr_id, len(value)) + value


def _aes_cbc_encrypt(key16: bytes, plaintext: bytes) -> bytes:
    pad = 16 - (len(plaintext) % 16)
    plaintext = plaintext + bytes([pad] * pad)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key16), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()


def build_enrollee_m2_eap(
    m1: WscMessage,
    pin: str,
    enrollee_nonce: bytes,
    *,
    sta_mac: bytes,
    ap_mac: bytes,
) -> bytes:
    """Build EAP-WSC M2 carrying the given 8-digit PIN."""
    r_nonce = m1.attributes.get(_ATTR_REGISTRAR_NONCE)
    if not r_nonce:
        raise ValueError("M1 missing registrar nonce")

    dh_priv = rsa.generate_private_key(public_exponent=65537, key_size=1024, backend=default_backend())
    dh_pub = dh_priv.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    k_plain = hashlib.sha256(b"".join(sorted([sta_mac, ap_mac])) + enrollee_nonce + r_nonce).digest()
    authkey = _kdf(k_plain, b"WPS AuthKey")
    wrapkey = _kdf(k_plain, b"WPS KeyWrapKey")[:16]

    pin_tlv = _build_attr(_ATTR_DEV_PASSWORD_ID, struct.pack(">H", 0)) + _build_attr(
        _PIN_ATTR_ID, pin.encode("ascii")
    )
    enc_settings = _aes_cbc_encrypt(wrapkey, pin_tlv)

    body = b"".join(
        [
            _build_attr(_ATTR_VERSION, bytes([0x10])),
            _build_attr(_ATTR_MSG_TYPE, bytes([5])),
            _build_attr(_ATTR_ENROLLEE_NONCE, enrollee_nonce),
            _build_attr(_ATTR_REGISTRAR_NONCE, r_nonce),
            _build_attr(_ATTR_PUBLIC_KEY, dh_pub),
            _build_attr(_ENC_SETTINGS_ATTR, enc_settings),
        ]
    )
    auth = hmac.new(authkey, body, hashlib.sha256).digest()[:8]
    body += _build_attr(_ATTR_AUTHENTICATOR, auth)

    wsc_inner = WSC_OUI + bytes([0, 4]) + body
    eap = bytes([0x02, 0x01]) + struct.pack(">H", 5 + len(wsc_inner)) + bytes([254]) + wsc_inner
    eapol = bytes([1, 0]) + struct.pack(">H", len(eap)) + eap
    return LLC_SNAP_EAPOL + eapol


def new_enrollee_nonce() -> bytes:
    return os.urandom(16)