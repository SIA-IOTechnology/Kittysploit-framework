#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""mDNS / DNS-SD client — unicast + multicast browse with PTR/SRV/TXT/A parsing."""

from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353


@dataclass
class DnsRecord:
    name: str
    rtype: int
    ttl: int = 0
    data: bytes = b""
    text: str = ""


@dataclass
class MdnsService:
    """Resolved DNS-SD instance (PTR → SRV/TXT/A)."""

    instance: str = ""
    service_type: str = ""
    host: str = ""
    port: int = 0
    priority: int = 0
    weight: int = 0
    addresses: List[str] = field(default_factory=list)
    txt: Dict[str, str] = field(default_factory=dict)
    raw_names: List[str] = field(default_factory=list)


@dataclass
class MdnsEnumResult:
    detected: bool = False
    services: List[MdnsService] = field(default_factory=list)
    names: List[str] = field(default_factory=list)
    queries_hit: List[str] = field(default_factory=list)
    suggested_modules: List[str] = field(default_factory=list)
    error: str = ""
    mode: str = "unicast"


def _encode_name(name: str) -> bytes:
    out = b""
    for label in str(name or "").strip(".").split("."):
        if not label:
            continue
        raw = label.encode("utf-8")
        if len(raw) > 63:
            raw = raw[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _decode_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    jumped = False
    original = offset
    hops = 0
    while offset < len(data) and hops < 32:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                original = offset + 2
                jumped = True
            offset = pointer
            hops += 1
            continue
        if length > 63 or offset + 1 + length > len(data):
            break
        labels.append(data[offset + 1 : offset + 1 + length].decode("utf-8", errors="ignore"))
        offset += 1 + length
        hops += 1
    name = ".".join(labels)
    return name, (original if jumped else offset)


def build_query(name: str, qtype: int = 12) -> bytes:
    """DNS query (qtype 12=PTR, 33=SRV, 16=TXT, 1=A, 255=ANY)."""
    header = struct.pack("!HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
    return header + _encode_name(name) + struct.pack("!HH", int(qtype) & 0xFFFF, 1)


def parse_dns_message(data: bytes) -> List[DnsRecord]:
    if len(data) < 12:
        return []
    try:
        _id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    except struct.error:
        return []
    offset = 12
    # skip questions
    for _ in range(qdcount):
        _name, offset = _decode_name(data, offset)
        offset += 4
        if offset > len(data):
            return []
    records: List[DnsRecord] = []
    total = ancount + nscount + arcount
    for _ in range(total):
        if offset + 10 > len(data):
            break
        name, offset = _decode_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        if offset + rdlength > len(data):
            break
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        text = ""
        if rtype == 12:  # PTR
            text, _ = _decode_name(data, offset - rdlength)
        elif rtype == 1 and rdlength == 4:  # A
            text = socket.inet_ntoa(rdata)
        elif rtype == 28 and rdlength == 16:  # AAAA
            try:
                text = socket.inet_ntop(socket.AF_INET6, rdata)
            except OSError:
                text = rdata.hex()
        elif rtype == 16:  # TXT
            parts: List[str] = []
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                i += 1
                parts.append(rdata[i : i + ln].decode("utf-8", errors="ignore"))
                i += ln
            text = "\n".join(parts)
        elif rtype == 33 and rdlength >= 6:  # SRV
            priority, weight, port = struct.unpack("!HHH", rdata[:6])
            target, _ = _decode_name(data, offset - rdlength + 6)
            text = f"{priority} {weight} {port} {target}"
        records.append(DnsRecord(name=name, rtype=rtype, ttl=ttl, data=rdata, text=text))
    return records


def _parse_txt_map(txt_blob: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in str(txt_blob or "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
        elif line.strip():
            out[line.strip()] = ""
    return out


def _parse_srv(text: str) -> Tuple[int, int, int, str]:
    parts = str(text or "").split()
    if len(parts) < 4:
        return 0, 0, 0, ""
    try:
        return int(parts[0]), int(parts[1]), int(parts[2]), parts[3]
    except ValueError:
        return 0, 0, 0, parts[-1] if parts else ""


def records_to_services(records: Sequence[DnsRecord]) -> List[MdnsService]:
    """Correlate PTR/SRV/TXT/A into service instances."""
    by_name: Dict[str, List[DnsRecord]] = {}
    for rec in records:
        key = rec.name.lower().rstrip(".")
        by_name.setdefault(key, []).append(rec)

    services: List[MdnsService] = []
    seen = set()

    ptr_targets = [r.text for r in records if r.rtype == 12 and r.text]
    # Also treat SRV owners as instances when no PTR
    if not ptr_targets:
        ptr_targets = [r.name for r in records if r.rtype == 33]

    for instance in ptr_targets:
        inst_key = instance.lower().rstrip(".")
        if not inst_key or inst_key in seen:
            continue
        seen.add(inst_key)
        svc = MdnsService(instance=instance, raw_names=[instance])
        # service type from instance: name._type._tcp.local
        parts = [p for p in inst_key.split(".") if p]
        for i, part in enumerate(parts):
            if part.startswith("_") and i + 1 < len(parts) and parts[i + 1] in ("_tcp", "_udp"):
                svc.service_type = f"{part}.{parts[i + 1]}"
                break

        for rec in by_name.get(inst_key, []):
            if rec.rtype == 33:
                prio, weight, port, target = _parse_srv(rec.text)
                svc.priority, svc.weight, svc.port = prio, weight, port
                svc.host = target
            elif rec.rtype == 16:
                svc.txt.update(_parse_txt_map(rec.text))

        if svc.host:
            host_key = svc.host.lower().rstrip(".")
            for rec in by_name.get(host_key, []):
                if rec.rtype in (1, 28) and rec.text:
                    if rec.text not in svc.addresses:
                        svc.addresses.append(rec.text)
            # also scan all A records matching host
            for rec in records:
                if rec.rtype in (1, 28) and rec.name.lower().rstrip(".") == host_key and rec.text:
                    if rec.text not in svc.addresses:
                        svc.addresses.append(rec.text)

        services.append(svc)

    # Fallback: orphan A/TXT names as lightweight entries
    if not services:
        names = sorted({r.name for r in records if r.name})
        for name in names[:24]:
            services.append(MdnsService(instance=name, raw_names=[name]))
    return services


class MdnsClient:
    """Session-style mDNS probe helper (UDP)."""

    def __init__(self, timeout: float = 2.0, port: int = MDNS_PORT):
        self.timeout = float(timeout)
        self.port = int(port)
        self.last_error = ""
        self.last_records: List[DnsRecord] = []

    def _collect(
        self,
        sock: socket.socket,
        duration: float,
    ) -> List[DnsRecord]:
        deadline = time.time() + max(0.2, duration)
        records: List[DnsRecord] = []
        sock.settimeout(0.3)
        while time.time() < deadline:
            try:
                data, _addr = sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError as exc:
                self.last_error = str(exc)
                break
            records.extend(parse_dns_message(data))
        self.last_records = records
        return records

    def query_unicast(self, host: str, name: str, qtype: int = 12) -> List[DnsRecord]:
        self.last_error = ""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(self.timeout)
            sock.sendto(build_query(name, qtype), (host, self.port))
            return self._collect(sock, self.timeout)
        except OSError as exc:
            self.last_error = str(exc)
            return []
        finally:
            sock.close()

    def query_multicast(self, name: str, qtype: int = 12, duration: Optional[float] = None) -> List[DnsRecord]:
        self.last_error = ""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("", self.port))
            except OSError:
                # Fall back to ephemeral bind if 5353 busy
                sock.bind(("", 0))
            try:
                sock.setsockopt(
                    socket.IPPROTO_IP,
                    socket.IP_ADD_MEMBERSHIP,
                    struct.pack("=4s4s", socket.inet_aton(MDNS_ADDR), socket.inet_aton("0.0.0.0")),
                )
            except OSError:
                pass
            sock.sendto(build_query(name, qtype), (MDNS_ADDR, self.port))
            return self._collect(sock, float(duration if duration is not None else self.timeout))
        except OSError as exc:
            self.last_error = str(exc)
            return []
        finally:
            sock.close()

    def enumerate(
        self,
        host: str = "",
        *,
        queries: Sequence[str] | None = None,
        multicast: bool = False,
        resolve_srv: bool = True,
    ) -> MdnsEnumResult:
        from lib.scanner.mdns.detectors import DEFAULT_IOT_QUERIES, suggest_modules_from_mdns

        result = MdnsEnumResult(mode="multicast" if multicast else "unicast")
        qlist = list(queries or DEFAULT_IOT_QUERIES)
        all_records: List[DnsRecord] = []
        hits: List[str] = []

        for q in qlist:
            if multicast or not host:
                recs = self.query_multicast(q)
            else:
                recs = self.query_unicast(host, q)
            if recs:
                hits.append(q)
                all_records.extend(recs)

        if resolve_srv and all_records:
            # Follow PTR targets with SRV/TXT/ANY on same transport
            ptrs = [r.text for r in all_records if r.rtype == 12 and r.text]
            for target in ptrs[:24]:
                for qtype in (33, 16, 255):
                    if multicast or not host:
                        all_records.extend(self.query_multicast(target, qtype))
                    else:
                        all_records.extend(self.query_unicast(host, target, qtype))

        services = records_to_services(all_records)
        names: List[str] = []
        seen = set()
        for svc in services:
            for label in [svc.instance, svc.service_type] + list(svc.raw_names):
                text = str(label or "").strip()
                if text and text not in seen:
                    seen.add(text)
                    names.append(text)
            if svc.service_type and svc.service_type not in seen:
                seen.add(svc.service_type)
                names.append(svc.service_type)

        result.services = services
        result.names = names
        result.queries_hit = hits
        result.suggested_modules = suggest_modules_from_mdns(names)
        result.detected = bool(services or hits)
        if not result.detected:
            result.error = self.last_error or "no_mdns_services"
        return result
