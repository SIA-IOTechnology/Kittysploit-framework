#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Passive ICS/SCADA sniffer — live capture or PCAP replay via Scapy.

Observes industrial traffic without transmitting packets to the monitored network.
Place the capture interface on a SPAN/mirror port or network TAP.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, DefaultDict, Dict, List

from kittysploit import *
from lib.protocols.ics.bacnet import parse_bacnet
from lib.protocols.ics.constants import DEFAULT_ICS_BPF, ICS_TCP_PORTS, ICS_UDP_PORTS
from lib.protocols.ics.device_classifier import (
    infer_device_role,
    infer_device_type,
    load_oui_database,
    lookup_vendor,
    summarize_device,
)
from lib.protocols.ics.dnp3 import parse_dnp3
from lib.protocols.ics.iec104 import parse_iec104
from lib.protocols.ics.modbus_tcp import parse_modbus_tcp
from lib.protocols.ics.purdue import apply_purdue_levels, detect_purdue_violations
from lib.protocols.ics.report import build_report, save_report
from lib.protocols.ics.s7comm import parse_s7comm


class Module(Auxiliary):
    __info__ = {
        "name": "ICS Passive Sniffer",
        "description": (
            "Passively discover OT/ICS assets by sniffing traffic with Scapy on a "
            "SPAN/TAP interface or by replaying a PCAP. Parses Modbus TCP, S7comm, "
            "DNP3, BACnet/IP, and IEC 104; flags write paths and Purdue violations; "
            "exports JSON and syncs the workspace. No packets are sent to the network."
        ),
        "author": ["KittySploit Team"],
        "tags": [
            "scanner",
            "ics",
            "scada",
            "ot",
            "passive",
            "modbus",
            "s7comm",
            "dnp3",
            "bacnet",
            "iec104",
            "purdue",
            "sniff",
            "discovery",
        ],
        "references": [
            "https://attack.mitre.org/techniques/T0846/",
            "https://github.com/valinorintelligence/Gridwolf",
        ],
        "attack": {
            "tactics": ["TA0007", "Discovery"],
            "techniques": ["T0846"],
            "prerequisites": [
                "SPAN/mirror port or network TAP on the OT segment",
                "Root or CAP_NET_RAW on the capture interface",
                "Promiscuous mode enabled on the sniffing NIC",
            ],
            "detections": [
                "Passive monitoring on a mirrored switch port",
            ],
            "artifacts": [
                "Optional PCAP and JSON report files on operator host",
            ],
        },
        "agent": {
            "risk": "passive",
            "effects": ["network_sniff"],
            "expected_requests": 0,
            "reversible": True,
            "approval_required": False,
            "produces": ["endpoints", "tech_hints", "risk_signals"],
            "chain": {
                "produces_capabilities": ["ot_assets"],
                "suggested_followups": [
                    "auxiliary/scanner/ics/modbus_identify",
                    "auxiliary/scanner/ics/s7comm_identify",
                    "auxiliary/scanner/ics/dnp3_identify",
                    "auxiliary/scanner/ics/bacnet_whois",
                ],
            },
        },
    }

    iface = OptString("eth0", "Live capture interface (SPAN/TAP)", required=False)
    pcap_file = OptString("", "PCAP file to replay (skips live capture when set)", required=False)
    timeout = OptInteger(60, "Live capture duration in seconds", required=False)
    bpf_filter = OptString(
        DEFAULT_ICS_BPF,
        "Berkeley Packet Filter expression (Scapy/tcpdump syntax)",
        required=False,
    )
    save_pcap = OptString(
        "",
        "Save live-captured packets to this PCAP path (empty = do not save)",
        required=False,
    )
    output_file = OptString(
        "",
        "JSON report output path (empty = auto ics_passive_<timestamp>.json)",
        required=False,
    )
    promisc = OptBool(True, "Enable promiscuous mode on the capture interface", required=False)

    def check(self):
        try:
            from scapy.all import IP, TCP, UDP, sniff  # noqa: F401
        except ImportError:
            print_error("scapy is not installed. Install it with: pip install scapy")
            return False

        pcap = str(self.pcap_file or "").strip()
        iface = str(self.iface or "").strip()
        if not pcap and not iface:
            print_error("Set PCAP_FILE for offline replay or IFACE for live capture")
            return False

        if not pcap:
            try:
                from scapy.all import get_if_list

                if iface not in get_if_list():
                    print_warning(f"Interface {iface} not found in scapy interface list")
            except Exception:
                pass

        return True

    def run(self):
        from scapy.all import IP, TCP, UDP, Ether, PcapReader, sniff, wrpcap

        pcap = str(self.pcap_file or "").strip()
        iface = str(self.iface or "eth0").strip()
        timeout = max(1, int(self.timeout or 60))
        bpf = str(self.bpf_filter or DEFAULT_ICS_BPF).strip()
        save_path = str(self.save_pcap or "").strip()
        promisc = bool(self.promisc)
        started_at = time.time()

        devices: DefaultDict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "ip": "",
                "mac": None,
                "vendor": "Unknown",
                "protocols": set(),
                "roles": set(),
                "peers": set(),
                "packet_count": 0,
                "device_type": "Unknown",
                "purdue_level": 0,
            }
        )
        flow_counts: DefaultDict[tuple[str, str, int, str], int] = defaultdict(int)
        flow_records: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        captured_packets: List[Any] = []
        packet_total = 0
        oui_db = load_oui_database()

        def register_device(ip: str, mac: str | None = None) -> Dict[str, Any]:
            entry = devices[ip]
            entry["ip"] = ip
            if mac and (not entry["mac"] or entry["mac"] == "Unknown"):
                entry["mac"] = mac
                entry["vendor"] = lookup_vendor(mac, oui_db)
            entry["packet_count"] += 1
            return entry

        def add_finding(**details: Any) -> None:
            findings.append(details)

        def record_flow(
            *,
            src: str,
            dst: str,
            protocol: str,
            transport: str,
            port: int,
            is_write: bool = False,
            is_program_transfer: bool = False,
            detail: str = "",
        ) -> None:
            key = (src, dst, port, protocol)
            flow_counts[key] += 1
            flow_records.append(
                {
                    "src": src,
                    "dst": dst,
                    "protocol": protocol,
                    "transport": transport,
                    "port": port,
                    "is_write": is_write,
                    "is_program_transfer": is_program_transfer,
                    "detail": detail,
                }
            )

        def handle_parsed_protocol(
            *,
            protocol_name: str,
            parsed: dict[str, Any],
            src: str,
            dst: str,
            sport: int,
            dport: int,
            transport: str,
            service_port: int,
            to_server: bool,
            client: Dict[str, Any],
            server: Dict[str, Any],
        ) -> None:
            is_write = bool(parsed.get("is_write"))
            is_program = bool(parsed.get("is_program_transfer"))
            role = infer_device_role(
                protocol_name,
                to_server=to_server,
                is_write=is_write,
            )
            if to_server:
                client["roles"].add(role)
            else:
                server["roles"].add(role)

            record_flow(
                src=src,
                dst=dst,
                protocol=protocol_name,
                transport=transport,
                port=service_port,
                is_write=is_write,
                is_program_transfer=is_program,
            )

            if is_write and to_server:
                add_finding(
                    severity="high",
                    type=f"{protocol_name.replace('-', '_')}_write",
                    protocol=protocol_name,
                    src=src,
                    dst=dst,
                    detail=f"{protocol_name} write from {src} to {dst}",
                )
                print_warning(f"{protocol_name} WRITE | {src}:{sport} -> {dst}:{dport}")

            elif is_program and to_server:
                add_finding(
                    severity="critical",
                    type="s7_program_transfer",
                    protocol=protocol_name,
                    src=src,
                    dst=dst,
                    job_type=parsed.get("job_type"),
                    detail=f"S7 program transfer from {src} to {dst}",
                )
                print_warning(f"S7 program transfer | {src} -> {dst}")

            elif parsed.get("is_discovery"):
                print_status(f"BACnet {parsed.get('bvlc_function_name')} | {src} -> {dst}")

            elif parsed.get("is_request") and to_server:
                print_status(
                    f"{protocol_name} request | {src} -> {dst} | "
                    f"fc={parsed.get('function_code') or parsed.get('type_id') or parsed.get('apdu_type')}"
                )
            else:
                print_status(f"{protocol_name} | {src}:{sport} -> {dst}:{dport}")

        def process_packet(packet: Any) -> None:
            nonlocal packet_total
            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]
            src = ip_layer.src
            dst = ip_layer.dst
            payload = b""
            sport = 0
            dport = 0
            transport = ""
            service_port = None
            to_server = False

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                sport = int(tcp_layer.sport)
                dport = int(tcp_layer.dport)
                payload = bytes(tcp_layer.payload)
                transport = "tcp"
                service_port = dport if dport in ICS_TCP_PORTS else sport if sport in ICS_TCP_PORTS else None
                to_server = dport in ICS_TCP_PORTS
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                sport = int(udp_layer.sport)
                dport = int(udp_layer.dport)
                payload = bytes(udp_layer.payload)
                transport = "udp"
                service_port = dport if dport in ICS_UDP_PORTS else sport if sport in ICS_UDP_PORTS else None
                to_server = dport in ICS_UDP_PORTS
            else:
                return

            if service_port is None:
                return

            packet_total += 1
            src_mac = packet[Ether].src if packet.haslayer(Ether) else None

            if transport == "tcp":
                protocol_name = ICS_TCP_PORTS[service_port]
            else:
                protocol_name = ICS_UDP_PORTS[service_port]

            server_ip = dst if to_server else src
            client_ip = src if to_server else dst

            server = register_device(server_ip)
            client = register_device(client_ip, src_mac if src == client_ip else None)
            server["protocols"].add(protocol_name)
            client["protocols"].add(protocol_name)
            server["peers"].add(client_ip)
            client["peers"].add(server_ip)

            parsed = None
            if protocol_name == "modbus-tcp" and payload:
                parsed = parse_modbus_tcp(payload)
            elif protocol_name == "s7comm" and payload:
                parsed = parse_s7comm(payload)
            elif protocol_name == "dnp3" and payload:
                parsed = parse_dnp3(payload)
            elif protocol_name == "bacnet" and payload:
                parsed = parse_bacnet(payload)
            elif protocol_name == "iec104" and payload:
                parsed = parse_iec104(payload)

            if parsed:
                handle_parsed_protocol(
                    protocol_name=protocol_name,
                    parsed=parsed,
                    src=src,
                    dst=dst,
                    sport=sport,
                    dport=dport,
                    transport=transport,
                    service_port=service_port,
                    to_server=to_server,
                    client=client,
                    server=server,
                )
                return

            role = infer_device_role(protocol_name, to_server=to_server)
            if to_server:
                client["roles"].add(role)
            else:
                server["roles"].add(role)
            record_flow(
                src=src,
                dst=dst,
                protocol=protocol_name,
                transport=transport,
                port=service_port,
            )
            print_status(f"{protocol_name} | {src}:{sport} -> {dst}:{dport}")

        print_info("=" * 72)
        if pcap:
            print_info(f"Replaying PCAP: {pcap}")
            try:
                with PcapReader(pcap) as reader:
                    for packet in reader:
                        process_packet(packet)
            except FileNotFoundError:
                print_error(f"PCAP file not found: {pcap}")
                return False
            except Exception as exc:
                print_error(f"Failed to read PCAP: {exc}")
                return False
        else:
            print_info(f"Live ICS sniff on {iface} for {timeout}s (promisc={promisc})")
            print_info(f"BPF filter: {bpf}")
            print_status("Listening — Ctrl+C to stop early. No packets will be transmitted.")

            def on_packet(packet: Any) -> None:
                process_packet(packet)
                if save_path:
                    captured_packets.append(packet)

            try:
                sniff(
                    iface=iface,
                    filter=bpf,
                    prn=on_packet,
                    timeout=timeout,
                    store=0,
                    promisc=promisc,
                )
            except PermissionError:
                print_error(
                    f"Permission denied capturing on {iface}. "
                    "Run as root or grant CAP_NET_RAW."
                )
                return False
            except OSError as exc:
                print_error(f"Could not sniff on {iface}: {exc}")
                print_info("Tip: use a SPAN/TAP interface and verify the NIC name with `ip link`")
                return False
            except KeyboardInterrupt:
                print_warning("Capture interrupted by user")

            if save_path and captured_packets:
                try:
                    wrpcap(save_path, captured_packets)
                    print_success(f"Saved {len(captured_packets)} packet(s) to {save_path}")
                except Exception as exc:
                    print_error(f"Failed to write PCAP: {exc}")

        for device in devices.values():
            device["device_type"] = infer_device_type(device["protocols"], device["roles"])

        apply_purdue_levels(devices)
        purdue_findings = detect_purdue_violations(devices, flow_records)
        findings.extend(purdue_findings)

        elapsed = time.time() - started_at
        capture_meta = {
            "mode": "pcap" if pcap else "live",
            "iface": iface if not pcap else None,
            "pcap_file": pcap or None,
            "timeout": timeout if not pcap else None,
            "bpf_filter": bpf,
            "elapsed_seconds": round(elapsed, 2),
            "save_pcap": save_path or None,
        }

        unique_flows = [
            {
                "src": src,
                "dst": dst,
                "port": port,
                "protocol": protocol,
                "packets": count,
            }
            for (src, dst, port, protocol), count in sorted(flow_counts.items())
        ]

        report = build_report(
            devices=devices,
            flows=unique_flows,
            findings=findings,
            packet_total=packet_total,
            capture=capture_meta,
        )

        print_info("=" * 72)
        print_info(f"Packets processed: {packet_total}")
        print_info(f"ICS endpoints discovered: {len(devices)}")
        print_info(f"Security findings: {len(findings)}")
        print_info(f"Unique flows: {len(unique_flows)}")

        if devices:
            print_success("Device inventory")
            for ip in sorted(devices):
                device = devices[ip]
                print_info(
                    f"  {summarize_device(device)} | purdue=L{device.get('purdue_level', 0)}"
                )

        if findings:
            print_warning("Security findings")
            for item in findings:
                print_warning(f"  [{item['severity']}] {item['detail']}")

        if not devices:
            print_warning(
                "No ICS traffic observed — verify SPAN/TAP wiring, BPF filter, "
                "and that the capture window overlaps plant activity"
            )
            return False

        output_path = str(self.output_file or "").strip()
        if not output_path:
            output_path = f"ics_passive_{int(time.time())}.json"
        try:
            save_report(output_path, report)
            print_success(f"JSON report saved to {output_path}")
            self.last_report_path = output_path
        except Exception as exc:
            print_error(f"Failed to save JSON report: {exc}")

        saved = self._sync_workspace(report)
        if saved:
            print_info(f"Workspace updated: {saved} ICS service record(s) saved")

        protocols = sorted({
            str(p).lower()
            for dev in devices.values()
            for p in (dev.get("protocols") or [])
        })
        self.vulnerability_info = {
            "ot_assets": len(devices),
            "protocols": protocols,
            "findings_count": len(findings),
            "report_path": output_path,
        }
        return report

    def _sync_workspace(self, report: Dict[str, Any]) -> int:
        if not getattr(self, "framework", None):
            return 0
        try:
            from core.workspace_intel import WorkspaceIntelStore

            return WorkspaceIntelStore(self.framework).record_ics_passive_scan(report)
        except Exception as exc:
            print_warning(f"Could not update workspace: {exc}")
            return 0
