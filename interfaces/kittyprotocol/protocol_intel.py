#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Rich protocol extraction on top of Scapy layers (not only port heuristics).
Best-effort: layers vary by Scapy build and capture quality.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional

_QUIC_LONG = re.compile(rb"\xcd\xf2\x1c\xc0", re.I)  # common QUIC version bytes in long header (approx)


def _tls_client_hello_sni(packet) -> str:
    try:
        from scapy.layers.tls.handshake import TLSClientHello, TLSExtServerName
    except Exception:
        return ""
    try:
        if not packet.haslayer(TLSClientHello):
            return ""
        hello = packet[TLSClientHello]
        for ext in getattr(hello, "ext", []) or []:
            if ext is None:
                continue
            if ext.name == "TLS Extension - Server Name Indication" or isinstance(ext, TLSExtServerName):
                names = getattr(ext, "server_names", None) or getattr(ext, "servernames", None) or []
                for sn in names:
                    name = getattr(sn, "servername", None) or getattr(sn, "server_name", None)
                    if name:
                        if isinstance(name, bytes):
                            return name.decode("utf-8", errors="ignore").strip("\x00.")
                        return str(name).strip("\x00.")
    except Exception:
        return ""
    return ""


def _tls_ja3_fingerprint(packet) -> str:
    """TLS JA3-style MD5 over GREASE-stripped tuple (client hello only)."""
    try:
        from scapy.layers.tls.handshake import TLSClientHello
    except Exception:
        return ""
    try:
        if not packet.haslayer(TLSClientHello):
            return ""
        hello = packet[TLSClientHello]
        vers = int(getattr(hello, "version", 0) or 0)
        ciphers: List[int] = []
        for c in getattr(hello, "ciphers", None) or []:
            try:
                val = int(c)
            except (TypeError, ValueError):
                continue
            if val in (0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA):
                continue
            ciphers.append(val)
        exts: List[int] = []
        groups: List[int] = []
        ec: List[int] = []
        for ext in getattr(hello, "ext", []) or []:
            if ext is None:
                continue
            etype = int(getattr(ext, "type", 0) or 0)
            if etype in (0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA):
                continue
            exts.append(etype)
            if ext.name and "Supported Groups" in ext.name:
                for g in getattr(ext, "groups", []) or []:
                    try:
                        groups.append(int(g))
                    except (TypeError, ValueError):
                        pass
            if ext.name and "EC Point Formats" in ext.name:
                for f in getattr(ext, "ecpl", []) or []:
                    try:
                        ec.append(int(f))
                    except (TypeError, ValueError):
                        pass
        ja3_str = f"{vers},{'-'.join(map(str, ciphers))},{'-'.join(map(str, exts))},{'-'.join(map(str, groups))},{'-'.join(map(str, ec))}"
        return hashlib.md5(ja3_str.encode()).hexdigest()
    except Exception:
        return ""


def _tls_certificate_hints(packet) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        cert_layer = packet.getlayer("TLSCertificate")
        if cert_layer is None:
            return out
        certs = getattr(cert_layer, "certs", None) or []
        if not certs:
            return out
        cert = certs[0]
        parsed = getattr(cert, "x509Cert", None) or getattr(cert, "x509", None) or cert
        issuer = getattr(parsed, "issuer", None)
        subject = getattr(parsed, "subject", None)
        not_before = getattr(parsed, "notBefore", None)
        not_after = getattr(parsed, "notAfter", None)
        serial = getattr(parsed, "serial", None)
        if issuer:
            out["tls.cert.issuer"] = str(issuer)[:220]
        if subject:
            out["tls.cert.subject"] = str(subject)[:220]
        if not_before:
            out["tls.cert.not_before"] = str(not_before)[:80]
        if not_after:
            out["tls.cert.not_after"] = str(not_after)[:80]
        if serial is not None:
            out["tls.cert.serial"] = str(serial)[:80]
    except Exception:
        pass
    return out


def _dns_fields(packet) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        if not packet.haslayer("DNS"):
            return out
        dns = packet["DNS"]
        if getattr(dns, "opcode", None) is not None:
            out["dns.opcode"] = str(int(dns.opcode))
        qd = getattr(dns, "qd", None)
        if qd and getattr(qd, "qname", None):
            qn = qd.qname
            if isinstance(qn, bytes):
                out["dns.qname"] = qn.decode("utf-8", errors="ignore").strip(".")
            else:
                out["dns.qname"] = str(qn).strip(".")
        if getattr(dns, "rcode", None) is not None:
            out["dns.rcode"] = str(int(dns.rcode))
        if getattr(dns, "ancount", None):
            out["dns.ancount"] = str(int(dns.ancount))
    except Exception:
        pass
    return out


def _mqtt_hint(raw: bytes) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if len(raw) < 2:
        return out
    pkt_type = (raw[0] >> 4) & 0x0F
    names = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 8: "SUBSCRIBE", 9: "SUBACK", 12: "PINGREQ", 13: "PINGRESP"}
    if pkt_type in names:
        out["mqtt.msgtype"] = names[pkt_type]
    return out


def _quic_hint(raw: bytes) -> Dict[str, str]:
    if _QUIC_LONG.search(raw[:40]) or (len(raw) > 1200 and raw[0] & 0x80):
        return {"quic.hint": "likely_quic_initial_or_long_header"}
    if raw.startswith(b"PRI * HTTP/2.0"):
        return {"http2.connection_preface": "PRI"}
    return {}


def enrich_packet_fields(packet, base_fields: Dict[str, str], protocol: str) -> Dict[str, str]:
    merged = dict(base_fields)
    try:
        raw = bytes(packet.getlayer("Raw").load) if packet.haslayer("Raw") else b""
    except Exception:
        raw = b""

    sni = _tls_client_hello_sni(packet)
    if sni:
        merged["tls.sni"] = sni[:200]
    ja3 = _tls_ja3_fingerprint(packet)
    if ja3:
        merged["tls.ja3_md5"] = ja3
    merged.update(_tls_certificate_hints(packet))

    merged.update(_dns_fields(packet))

    layers = {layer.__name__.upper() for layer in packet.layers()}
    if "SMB2" in layers or "SMB_HEADER" in layers or "SMB" in layers:
        merged["smb.layer"] = "1"
    if "KRB5" in layers or "KERBEROS" in layers:
        merged["kerberos.layer"] = "1"
    if "HTTP2" in layers or "H2FRAME" in layers:
        merged["http2.layer"] = "1"

    if protocol == "MQTT" and raw:
        merged.update(_mqtt_hint(raw))
    if protocol in ("TLS", "HTTP", "DNS") and raw:
        merged.update(_quic_hint(raw))
    return merged


def refine_protocol_label(packet, fallback: str, src_port: int, dst_port: int) -> str:
    layers = {layer.__name__.upper() for layer in packet.layers()}
    tls_ports = {443, 8443, 9443, 10443}
    if "HTTP2" in layers or "H2FRAME" in layers:
        return "HTTP2"
    if layers & {"TLS", "TLSRECORD", "TLSHANDSHAKE", "TLS13"}:
        return "TLS"
    if src_port in tls_ports or dst_port in tls_ports:
        if str(fallback or "").upper() in {"TCP", "UNKNOWN"}:
            return "TLS"
    if "DNS" in layers:
        return "DNS"
    if "SMB2" in layers or "SMB_HEADER" in layers or "SMB" in layers:
        return "SMB"
    if "KRB5" in layers or "KERBEROS" in layers:
        return "KERBEROS"
    if "MQTT" in layers:
        return "MQTT"
    try:
        raw = bytes(packet["Raw"].load) if packet.haslayer("Raw") else b""
    except Exception:
        raw = b""
    if packet.haslayer("UDP") and _quic_hint(raw):
        return "QUIC"
    return fallback
