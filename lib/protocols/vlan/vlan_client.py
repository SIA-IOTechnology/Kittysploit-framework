#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""802.1Q VLAN client mixin — tagged probes, CDP hints, and double-tag frames."""

from __future__ import annotations

import random
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set

from core.framework.base_module import BaseModule
from core.framework.option import OptFloat, OptInteger, OptString

CDP_MULTICAST = "01:00:0c:cc:cc:cc"
CDP_ETHERTYPE = 0x2000
DTP_ETHERTYPE = 0x2004
LLDP_MULTICAST = "01:80:c2:00:00:0e"
LLDP_ETHERTYPE = 0x88CC
CDP_NATIVE_VLAN_TLV = 0x0A
CDP_VOICE_VLAN_TLV = 0x0E

DTP_NEGOTIATION_MODES = {
    "auto": 0x05,
    "desirable": 0x03,
    "on": 0x04,
    "negotiate": 0x06,
}

CDP_CAPABILITIES = {
    0x01: "router",
    0x02: "transparent_bridge",
    0x04: "switch",
    0x08: "host",
    0x10: "igmp",
    0x20: "repeater",
}

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


@dataclass
class VlanProbeResult:
    vlan_id: int
    method: str
    detail: str = ""
    source: str = ""


@dataclass
class CdpHint:
    device_id: str = ""
    native_vlan: Optional[int] = None
    voice_vlan: Optional[int] = None
    platform: str = ""
    source_mac: str = ""
    port_id: str = ""
    ip_address: str = ""
    capabilities: str = ""
    software_version: str = ""


@dataclass
class LldpNeighbor:
    source_mac: str = ""
    chassis_id: str = ""
    port_id: str = ""
    system_name: str = ""
    system_description: str = ""
    management_address: str = ""
    port_vlan_id: Optional[int] = None
    vlan_name: str = ""


@dataclass
class DtpResult:
    frames_sent: int = 0
    trunk_negotiated: bool = False
    dtp_responses: List[dict] = field(default_factory=list)
    verified_vlans: List[VlanProbeResult] = field(default_factory=list)
    detail: str = ""


def _get_opt(instance: Any, name: str, default: Any = None) -> Any:
    value = getattr(instance, name, default)
    if hasattr(value, "value"):
        return value.value
    return value


def _normalize_mac(mac: str) -> str:
    cleaned = str(mac or "").strip().lower().replace("-", ":")
    if not _MAC_RE.match(cleaned):
        raise ValueError(f"invalid MAC address: {mac}")
    return cleaned


def _mac_to_bootp(mac: str) -> bytes:
    raw = bytes(int(part, 16) for part in _normalize_mac(mac).split(":"))
    return raw + b"\x00" * (16 - len(raw))


def _build_dhcp_discover(client_mac: str, xid: Optional[int] = None):
    from scapy.all import BOOTP, DHCP, IP, UDP

    transaction = xid if xid is not None else random.randint(1, 0xFFFFFFFF)
    return (
        IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(
            chaddr=_mac_to_bootp(client_mac),
            xid=transaction,
            flags=0x8000,
        )
        / DHCP(options=[("message-type", "discover"), "end"])
    )


def _wrap_dot1q(payload, vlan_id: int, src_mac: str, dst_mac: str = "ff:ff:ff:ff:ff:ff"):
    from scapy.all import Dot1Q, Ether

    return Ether(dst=dst_mac, src=src_mac) / Dot1Q(vlan=int(vlan_id)) / payload


def _wrap_double_dot1q(
    payload,
    native_vlan: int,
    target_vlan: int,
    src_mac: str,
    dst_mac: str = "ff:ff:ff:ff:ff:ff",
):
    from scapy.all import Dot1Q, Ether

    return (
        Ether(dst=dst_mac, src=src_mac)
        / Dot1Q(vlan=int(native_vlan))
        / Dot1Q(vlan=int(target_vlan))
        / payload
    )


def _build_arp_whois(
    src_mac: str,
    src_ip: str = "0.0.0.0",
    target_ip: str = "255.255.255.255",
):
    from scapy.all import ARP, Ether

    return Ether(dst="ff:ff:ff:ff:ff:ff", src=src_mac) / ARP(
        hwsrc=src_mac,
        psrc=src_ip,
        hwdst="00:00:00:00:00:00",
        pdst=target_ip,
        op=1,
    )


def _dhcp_offer_detail(packet) -> str:
    from scapy.all import BOOTP, DHCP

    bootp = packet.getlayer(BOOTP)
    if bootp and bootp.yiaddr:
        return f"offer={bootp.yiaddr}"
    dhcp = packet.getlayer(DHCP)
    if not dhcp or not dhcp.options:
        return "dhcp-offer"
    server = ""
    for opt in dhcp.options:
        if isinstance(opt, tuple) and opt[0] == "server_id":
            server = str(opt[1])
            break
    if server:
        return f"server={server}"
    return "dhcp-offer"


def _format_cdp_capabilities(raw: bytes) -> str:
    if len(raw) < 4:
        return ""
    flags = struct.unpack("!I", raw[:4])[0]
    labels = [name for bit, name in CDP_CAPABILITIES.items() if flags & bit]
    return ",".join(labels)


def _parse_cdp_address(raw: bytes) -> str:
    if len(raw) < 8:
        return ""
    for offset in range(4, len(raw) - 3):
        if raw[offset : offset + 2] == b"\x01\x01\xcc":
            addr_len = raw[offset + 2] if offset + 2 < len(raw) else 0
            start = offset + 3
            end = start + addr_len
            if end <= len(raw) and addr_len == 4:
                return ".".join(str(b) for b in raw[start:end])
    match = re.search(rb"(?:\x01\x01\xcc\x04)([\d\.]{7,15})", raw)
    if match:
        try:
            return match.group(1).decode(errors="ignore")
        except Exception:
            pass
    return ""


def _parse_cdp_frame(frame: bytes) -> Optional[CdpHint]:
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype != CDP_ETHERTYPE:
        return None

    src_mac = ":".join(f"{b:02x}" for b in frame[6:12])
    payload = frame[14:]
    if len(payload) < 4:
        return None

    tlvs = payload[4:]
    hint = CdpHint(source_mac=src_mac)
    offset = 0
    while offset + 4 <= len(tlvs):
        tlv_type = tlvs[offset]
        tlv_len = struct.unpack("!H", tlvs[offset + 2 : offset + 4])[0]
        if tlv_len < 4 or offset + tlv_len > len(tlvs):
            break
        value = tlvs[offset + 4 : offset + tlv_len]
        if tlv_type == 0x01:
            hint.device_id = value.decode(errors="ignore").strip()
        elif tlv_type == 0x02 and not hint.ip_address:
            hint.ip_address = _parse_cdp_address(value)
        elif tlv_type == 0x03:
            hint.port_id = value.decode(errors="ignore").strip()
        elif tlv_type == 0x04 and not hint.capabilities:
            hint.capabilities = _format_cdp_capabilities(value)
        elif tlv_type == 0x05:
            hint.software_version = value.decode(errors="ignore").strip()
        elif tlv_type == 0x06:
            hint.platform = value.decode(errors="ignore").strip()
        elif tlv_type == CDP_NATIVE_VLAN_TLV and len(value) >= 2:
            hint.native_vlan = struct.unpack("!H", value[:2])[0]
        elif tlv_type == CDP_VOICE_VLAN_TLV and len(value) >= 2:
            hint.voice_vlan = struct.unpack("!H", value[:2])[0]
        offset += tlv_len
    if not any(
        (
            hint.device_id,
            hint.native_vlan is not None,
            hint.voice_vlan is not None,
            hint.platform,
            hint.port_id,
        )
    ):
        return None
    return hint


def _parse_lldp_tlv_value(tlv_type: int, value: bytes) -> dict:
    parsed: Dict[str, Any] = {}
    if tlv_type == 1 and value:
        subtype = value[0]
        body = value[1:]
        if subtype == 4 and len(body) == 4:
            parsed["chassis_id"] = ".".join(str(b) for b in body)
        elif subtype == 7:
            parsed["chassis_id"] = body.hex()
        else:
            parsed["chassis_id"] = body.decode(errors="ignore").strip()
    elif tlv_type == 2 and value:
        parsed["port_id"] = value[1:].decode(errors="ignore").strip() if len(value) > 1 else value.decode(errors="ignore").strip()
    elif tlv_type == 5:
        parsed["system_name"] = value.decode(errors="ignore").strip()
    elif tlv_type == 6:
        parsed["system_description"] = value.decode(errors="ignore").strip()
    elif tlv_type == 8 and len(value) >= 9:
        addr_len = value[8]
        start = 9
        end = start + addr_len
        if end <= len(value) and addr_len == 4:
            parsed["management_address"] = ".".join(str(b) for b in value[start:end])
    elif tlv_type == 127 and len(value) >= 4:
        oui = value[:3]
        subtype = value[3]
        body = value[4:]
        if oui == b"\x00\x80\xc2":
            if subtype == 1 and len(body) >= 2:
                parsed["port_vlan_id"] = struct.unpack("!H", body[:2])[0]
            elif subtype == 3:
                parsed["vlan_name"] = body.decode(errors="ignore").strip("\x00")
    return parsed


def _parse_lldp_frame(frame: bytes) -> Optional[LldpNeighbor]:
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype != LLDP_ETHERTYPE:
        return None

    src_mac = ":".join(f"{b:02x}" for b in frame[6:12])
    payload = frame[14:]
    neighbor = LldpNeighbor(source_mac=src_mac)
    offset = 0
    while offset + 2 <= len(payload):
        header = struct.unpack("!H", payload[offset : offset + 2])[0]
        tlv_type = (header >> 9) & 0x7F
        tlv_len = header & 0x01FF
        offset += 2
        if tlv_type == 0 and tlv_len == 0:
            break
        if offset + tlv_len > len(payload):
            break
        value = payload[offset : offset + tlv_len]
        offset += tlv_len
        parsed = _parse_lldp_tlv_value(tlv_type, value)
        for key, val in parsed.items():
            setattr(neighbor, key, val)

    if not any(
        (
            neighbor.chassis_id,
            neighbor.system_name,
            neighbor.port_id,
            neighbor.port_vlan_id is not None,
        )
    ):
        return None
    return neighbor


def _build_dtp_payload(
    negotiation: str = "desirable",
    domain: str = "",
    device_id: str = "",
) -> bytes:
    neg_type = DTP_NEGOTIATION_MODES.get(str(negotiation or "desirable").lower(), 0x03)
    body = b"\x01"
    dom = (domain or "NULL").encode()
    body += struct.pack("!HH", 0x0001, 4 + len(dom)) + dom
    body += struct.pack("!HH", 0x0004, 5) + struct.pack("!B", 0x03)
    body += struct.pack("!HH", 0x0003, 5) + struct.pack("!B", neg_type)
    if device_id:
        nb = device_id.encode()
        body += struct.pack("!HH", 0x0005, 4 + len(nb)) + nb
    return body


def _build_dtp_frame(src_mac: str, negotiation: str = "desirable", device_id: str = ""):
    from scapy.all import Ether, Raw

    payload = _build_dtp_payload(negotiation=negotiation, device_id=device_id or src_mac.replace(":", ""))
    return Ether(dst=CDP_MULTICAST, src=src_mac, type=DTP_ETHERTYPE) / Raw(payload)


def _parse_dtp_frame(frame: bytes) -> Optional[dict]:
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype != DTP_ETHERTYPE:
        return None

    src_mac = ":".join(f"{b:02x}" for b in frame[6:12])
    payload = frame[14:]
    if len(payload) < 5:
        return None

    result = {
        "source_mac": src_mac,
        "domain": "",
        "status": "",
        "negotiation": "",
        "neighbor": "",
        "trunk": False,
    }
    offset = 1
    while offset + 4 <= len(payload):
        tlv_type = struct.unpack("!H", payload[offset : offset + 2])[0]
        tlv_len = struct.unpack("!H", payload[offset + 2 : offset + 4])[0]
        if tlv_len < 4 or offset + tlv_len > len(payload):
            break
        value = payload[offset + 4 : offset + tlv_len]
        if tlv_type == 0x0001:
            result["domain"] = value.decode(errors="ignore").strip()
        elif tlv_type == 0x0003 and value:
            code = value[0]
            result["negotiation"] = {
                0x03: "desirable",
                0x04: "on",
                0x05: "auto",
                0x06: "negotiate",
            }.get(code, f"type-{code}")
        elif tlv_type == 0x0004 and value:
            code = value[0]
            result["status"] = {0x02: "non-trunk", 0x03: "trunk"}.get(code, f"status-{code}")
            result["trunk"] = code == 0x03
        elif tlv_type == 0x0005:
            result["neighbor"] = value.decode(errors="ignore").strip()
        offset += tlv_len
    if not any((result["domain"], result["status"], result["negotiation"], result["neighbor"])):
        return None
    return result


class Vlan_client(BaseModule):
    """Mixin for 802.1Q VLAN scanner and hopping modules."""

    interface = OptString("eth0", "Ethernet interface connected to the target switch port", True)
    timeout = OptFloat(1.0, "Default probe timeout in seconds", False, advanced=True)
    cdp_timeout = OptFloat(3.0, "Seconds to listen for CDP native VLAN hints", False, advanced=True)
    native_vlan = OptInteger(
        1,
        "Assumed native/outer VLAN tag (1 is common; CDP can refine this)",
        False,
        advanced=True,
    )
    target_vlan = OptInteger(0, "Target VLAN ID for hop/probe operations", False, advanced=True)

    def _iface(self) -> str:
        return str(_get_opt(self, "interface", "") or "").strip()

    def _timeout(self, override: Optional[float] = None) -> float:
        if override is not None:
            return max(0.2, float(override))
        return max(0.2, float(_get_opt(self, "timeout", 1.0) or 1.0))

    def _cdp_timeout(self, override: Optional[float] = None) -> float:
        if override is not None:
            return max(0.0, float(override))
        return max(0.0, float(_get_opt(self, "cdp_timeout", 3.0) or 3.0))

    def _native_vlan(self, override: Optional[int] = None) -> int:
        if override is not None:
            return int(override)
        return int(_get_opt(self, "native_vlan", 1) or 1)

    def _target_vlan(self, override: Optional[int] = None) -> int:
        if override is not None:
            return int(override)
        return int(_get_opt(self, "target_vlan", 0) or 0)

    @staticmethod
    def vlan_require_scapy() -> bool:
        try:
            from scapy.all import Dot1Q, sendp  # noqa: F401
            return True
        except ImportError:
            return False

    def vlan_interface_mac(self, iface: Optional[str] = None) -> str:
        from scapy.all import get_if_hwaddr

        name = str(iface or self._iface() or "").strip()
        if not name:
            raise ValueError("interface is required")
        return _normalize_mac(get_if_hwaddr(name))

    @staticmethod
    def vlan_iter_ids(start: int, end: int, include: str = "") -> Iterable[int]:
        if str(include or "").strip():
            values: List[int] = []
            for part in str(include).split(","):
                part = part.strip()
                if not part:
                    continue
                if "-" in part:
                    left, right = part.split("-", 1)
                    values.extend(range(int(left), int(right) + 1))
                else:
                    values.append(int(part))
            return sorted({vid for vid in values if 1 <= vid <= 4094})

        low = max(1, int(start))
        high = min(4094, int(end))
        if low > high:
            low, high = high, low
        return range(low, high + 1)

    def vlan_sniff_cdp(
        self,
        iface: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> List[CdpHint]:
        from scapy.all import sniff

        name = str(iface or self._iface() or "").strip()
        wait = self._cdp_timeout(timeout)
        hints: List[CdpHint] = []
        seen: Set[str] = set()

        def _on_packet(packet):
            raw = bytes(packet)
            hint = _parse_cdp_frame(raw)
            if not hint:
                return
            key = f"{hint.source_mac}:{hint.native_vlan}:{hint.device_id}"
            if key in seen:
                return
            seen.add(key)
            hints.append(hint)

        sniff(
            iface=name,
            timeout=max(0.5, wait) if wait > 0 else 0.5,
            filter="ether dst 01:00:0c:cc:cc:cc",
            prn=_on_packet,
            store=0,
        )
        return hints

    def vlan_probe_dhcp(
        self,
        vlan_id: int,
        iface: Optional[str] = None,
        client_mac: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Optional[VlanProbeResult]:
        from scapy.all import BOOTP, DHCP, sniff, sendp

        name = str(iface or self._iface() or "").strip()
        mac = client_mac or self.vlan_interface_mac(name)
        wait = self._timeout(timeout)

        discover = _wrap_dot1q(_build_dhcp_discover(mac), vlan_id, mac)
        xid = discover[BOOTP].xid
        seen: Set[int] = set()

        def _match(packet) -> bool:
            if not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
                return False
            if packet[BOOTP].xid != xid:
                return False
            options = packet[DHCP].options or []
            for opt in options:
                if isinstance(opt, tuple) and opt[0] == "message-type" and opt[1] in (2, 5):
                    return True
            return False

        sendp(discover, iface=name, verbose=0)
        responses = sniff(iface=name, timeout=wait, lfilter=_match, store=1)
        for packet in responses:
            bootp = packet[BOOTP]
            if bootp.xid in seen:
                continue
            seen.add(bootp.xid)
            src = str(packet["Ether"].src) if packet.haslayer("Ether") else ""
            return VlanProbeResult(
                vlan_id=int(vlan_id),
                method="dhcp",
                detail=_dhcp_offer_detail(packet),
                source=src,
            )
        return None

    def vlan_probe_arp(
        self,
        vlan_id: int,
        target_ip: str,
        iface: Optional[str] = None,
        client_mac: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Optional[VlanProbeResult]:
        from scapy.all import ARP, sniff, sendp

        name = str(iface or self._iface() or "").strip()
        mac = client_mac or self.vlan_interface_mac(name)
        wait = self._timeout(timeout)

        request = _wrap_dot1q(_build_arp_whois(mac, target_ip=target_ip)[ARP], vlan_id, mac)

        def _match(packet) -> bool:
            return packet.haslayer(ARP) and packet[ARP].op == 2 and packet[ARP].psrc == target_ip

        sendp(request, iface=name, verbose=0)
        responses = sniff(iface=name, timeout=wait, lfilter=_match, store=1)
        if not responses:
            return None
        reply = responses[0]
        hwsrc = str(reply[ARP].hwsrc)
        return VlanProbeResult(
            vlan_id=int(vlan_id),
            method="arp",
            detail=f"host={hwsrc} ip={target_ip}",
            source=hwsrc,
        )

    def vlan_probe_double_tag(
        self,
        target_vlan: int,
        native_vlan: Optional[int] = None,
        iface: Optional[str] = None,
        client_mac: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> Optional[VlanProbeResult]:
        from scapy.all import BOOTP, DHCP, sniff, sendp

        name = str(iface or self._iface() or "").strip()
        mac = client_mac or self.vlan_interface_mac(name)
        outer = self._native_vlan(native_vlan)
        inner = int(target_vlan)
        wait = self._timeout(timeout)

        discover = _wrap_double_dot1q(_build_dhcp_discover(mac), outer, inner, mac)
        xid = discover[BOOTP].xid

        def _match(packet) -> bool:
            if not packet.haslayer(BOOTP) or not packet.haslayer(DHCP):
                return False
            if packet[BOOTP].xid != xid:
                return False
            options = packet[DHCP].options or []
            for opt in options:
                if isinstance(opt, tuple) and opt[0] == "message-type" and opt[1] in (2, 5):
                    return True
            return False

        sendp(discover, iface=name, verbose=0)
        responses = sniff(iface=name, timeout=wait, lfilter=_match, store=1)
        if not responses:
            return None
        packet = responses[0]
        src = str(packet["Ether"].src) if packet.haslayer("Ether") else ""
        return VlanProbeResult(
            vlan_id=inner,
            method="double-tag-dhcp",
            detail=_dhcp_offer_detail(packet),
            source=src,
        )

    def vlan_scan_ids(
        self,
        vlan_ids: Sequence[int],
        methods: Sequence[str],
        probe_ip: str,
        per_vlan_timeout: Optional[float] = None,
        iface: Optional[str] = None,
        client_mac: Optional[str] = None,
        progress: Optional[Callable[[int, int], None]] = None,
    ) -> List[VlanProbeResult]:
        name = str(iface or self._iface() or "").strip()
        mac = client_mac or self.vlan_interface_mac(name)
        wait = self._timeout(per_vlan_timeout)
        normalized = [item.strip().lower() for item in methods if str(item).strip()]
        results: List[VlanProbeResult] = []
        total = len(vlan_ids)

        for index, vlan_id in enumerate(vlan_ids, start=1):
            if progress:
                progress(index, total)
            hit: Optional[VlanProbeResult] = None
            if "dhcp" in normalized:
                hit = self.vlan_probe_dhcp(vlan_id, iface=name, client_mac=mac, timeout=wait)
            if not hit and "arp" in normalized and probe_ip:
                hit = self.vlan_probe_arp(
                    vlan_id,
                    target_ip=probe_ip,
                    iface=name,
                    client_mac=mac,
                    timeout=wait,
                )
            if hit:
                results.append(hit)
        return results

    @staticmethod
    def vlan_pick_native_from_cdp(hints: Sequence[CdpHint], fallback: int = 1) -> int:
        for hint in hints:
            if hint.native_vlan is not None:
                return int(hint.native_vlan)
        return int(fallback)

    @staticmethod
    def vlan_cdp_to_dict(hints: Sequence[CdpHint]) -> List[dict]:
        return [
            {
                "device_id": hint.device_id,
                "native_vlan": hint.native_vlan,
                "voice_vlan": hint.voice_vlan,
                "platform": hint.platform,
                "source_mac": hint.source_mac,
                "port_id": hint.port_id,
                "ip_address": hint.ip_address,
                "capabilities": hint.capabilities,
                "software_version": hint.software_version,
            }
            for hint in hints
        ]

    @staticmethod
    def vlan_lldp_to_dict(neighbors: Sequence[LldpNeighbor]) -> List[dict]:
        return [
            {
                "source_mac": item.source_mac,
                "chassis_id": item.chassis_id,
                "port_id": item.port_id,
                "system_name": item.system_name,
                "system_description": item.system_description,
                "management_address": item.management_address,
                "port_vlan_id": item.port_vlan_id,
                "vlan_name": item.vlan_name,
            }
            for item in neighbors
        ]

    def vlan_sniff_lldp(
        self,
        iface: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> List[LldpNeighbor]:
        from scapy.all import sniff

        name = str(iface or self._iface() or "").strip()
        wait = self._cdp_timeout(timeout)
        neighbors: List[LldpNeighbor] = []
        seen: Set[str] = set()

        def _on_packet(packet):
            raw = bytes(packet)
            neighbor = _parse_lldp_frame(raw)
            if not neighbor:
                return
            key = f"{neighbor.source_mac}:{neighbor.chassis_id}:{neighbor.port_id}"
            if key in seen:
                return
            seen.add(key)
            neighbors.append(neighbor)

        sniff(
            iface=name,
            timeout=max(0.5, wait) if wait > 0 else 0.5,
            filter="ether proto 0x88cc",
            prn=_on_packet,
            store=0,
        )
        return neighbors

    def vlan_enum_l2_neighbors(
        self,
        iface: Optional[str] = None,
        timeout: Optional[float] = None,
        listen_cdp: bool = True,
        listen_lldp: bool = True,
    ) -> dict:
        name = str(iface or self._iface() or "").strip()
        wait = self._cdp_timeout(timeout)
        cdp_neighbors: List[CdpHint] = []
        lldp_neighbors: List[LldpNeighbor] = []
        if listen_cdp:
            cdp_neighbors = self.vlan_sniff_cdp(iface=name, timeout=wait)
        if listen_lldp:
            lldp_neighbors = self.vlan_sniff_lldp(iface=name, timeout=wait)
        return {
            "interface": name,
            "cdp_neighbors": cdp_neighbors,
            "lldp_neighbors": lldp_neighbors,
        }

    def vlan_send_dtp(
        self,
        negotiation: str = "desirable",
        iface: Optional[str] = None,
        client_mac: Optional[str] = None,
        count: int = 1,
        interval: float = 2.0,
    ) -> int:
        from scapy.all import sendp

        name = str(iface or self._iface() or "").strip()
        mac = client_mac or self.vlan_interface_mac(name)
        sent = 0
        for _ in range(max(1, int(count))):
            frame = _build_dtp_frame(mac, negotiation=negotiation, device_id=mac.replace(":", ""))
            sendp(frame, iface=name, verbose=0)
            sent += 1
            if count > 1 and interval > 0:
                import time

                time.sleep(max(0.1, float(interval)))
        return sent

    def vlan_sniff_dtp(
        self,
        iface: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> List[dict]:
        from scapy.all import sniff

        name = str(iface or self._iface() or "").strip()
        wait = self._timeout(timeout)
        responses: List[dict] = []
        seen: Set[str] = set()

        def _on_packet(packet):
            raw = bytes(packet)
            parsed = _parse_dtp_frame(raw)
            if not parsed:
                return
            key = f"{parsed.get('source_mac')}:{parsed.get('status')}:{parsed.get('negotiation')}"
            if key in seen:
                return
            seen.add(key)
            responses.append(parsed)

        sniff(
            iface=name,
            timeout=max(0.5, wait),
            filter="ether dst 01:00:0c:cc:cc:cc",
            prn=_on_packet,
            store=0,
        )
        return responses

    def vlan_dtp_trunk_negotiate(
        self,
        negotiation: str = "desirable",
        duration: float = 10.0,
        interval: float = 2.0,
        verify_vlan_ids: Optional[Sequence[int]] = None,
        iface: Optional[str] = None,
        client_mac: Optional[str] = None,
        per_vlan_timeout: Optional[float] = None,
    ) -> DtpResult:
        import threading
        import time

        name = str(iface or self._iface() or "").strip()
        mac = client_mac or self.vlan_interface_mac(name)
        duration = max(1.0, float(duration))
        interval = max(0.5, float(interval))
        result = DtpResult()
        dtp_responses: List[dict] = []
        stop_event = threading.Event()

        def _listener():
            end = time.time() + duration + 1.0
            while not stop_event.is_set() and time.time() < end:
                try:
                    batch = self.vlan_sniff_dtp(iface=name, timeout=min(1.0, interval))
                    dtp_responses.extend(batch)
                except Exception:
                    break

        listener = threading.Thread(target=_listener, daemon=True)
        listener.start()

        end_time = time.time() + duration
        while time.time() < end_time:
            result.frames_sent += self.vlan_send_dtp(
                negotiation=negotiation,
                iface=name,
                client_mac=mac,
                count=1,
                interval=0,
            )
            time.sleep(interval)

        stop_event.set()
        listener.join(timeout=2.0)
        result.dtp_responses = dtp_responses
        result.trunk_negotiated = any(item.get("trunk") for item in dtp_responses)

        if verify_vlan_ids:
            verified = self.vlan_scan_ids(
                vlan_ids=list(verify_vlan_ids),
                methods=["dhcp"],
                probe_ip="",
                per_vlan_timeout=per_vlan_timeout,
                iface=name,
                client_mac=mac,
            )
            result.verified_vlans = verified
            if verified and not result.trunk_negotiated:
                result.trunk_negotiated = True
                result.detail = "tagged DHCP succeeded after DTP frames"

        if result.trunk_negotiated:
            trunk_peers = [item for item in dtp_responses if item.get("trunk")]
            if trunk_peers:
                peer = trunk_peers[0]
                result.detail = (
                    f"trunk status from {peer.get('source_mac')} "
                    f"({peer.get('status') or peer.get('negotiation')})"
                )
            elif result.verified_vlans:
                result.detail = f"verified VLANs: {', '.join(str(v.vlan_id) for v in result.verified_vlans)}"
        else:
            result.detail = "no trunk negotiation observed"
        return result
