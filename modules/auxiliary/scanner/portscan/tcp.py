#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Parallel TCP connect port scanner for authorized engagements."""

from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set, Tuple

from kittysploit import *


class Module(Auxiliary):
    __info__ = {
        "name": "TCP Port Scanner",
        "description": "Scan TCP ports on one or more hosts using parallel connect probes.",
        "author": ["KittySploit Team"],
        "tags": ["scanner", "portscan", "tcp", "discovery", "network"],
        "references": [
            "https://attack.mitre.org/techniques/T1046/",
        ],
        "attack": {
            "tactics": ["TA0007", "Discovery"],
            "techniques": ["T1046"],
            "prerequisites": [
                "Authorized network access to target host or CIDR",
                "Outbound TCP connectivity from operator host",
            ],
            "detections": [
                "Network IDS alert for horizontal port sweep",
                "Sigma: multiple failed/successful TCP connection attempts across ports",
            ],
            "artifacts": [
                "Firewall flow logs",
                "Zeek conn.log / NetFlow records",
            ],
        },
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints', 'params'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    rhosts = OptString("", "Target host, CIDR, or comma-separated list (e.g. 10.0.0.0/24)", required=True)
    ports = OptString("1-1024", "Ports: range (1-1000), list (22,80,443), or mixed", required=False)
    threads = OptInteger(50, "Concurrent probe threads", required=False)
    timeout = OptFloat(1.0, "Connect timeout per probe (seconds)", required=False)
    show_closed = OptBool(False, "Include closed/filtered ports in output", required=False)

    def run(self):
        targets = self._parse_targets(str(self.rhosts or "").strip())
        if not targets:
            print_error("No valid targets in rhosts")
            return False

        port_list = self._parse_ports(str(self.ports or "1-1024"))
        if not port_list:
            print_error("No valid ports to scan")
            return False

        threads = max(1, min(int(self.threads or 50), 256))
        timeout = max(0.2, float(self.timeout or 1.0))
        show_closed = bool(self.show_closed)

        print_info(f"TCP port scan: {len(targets)} host(s), {len(port_list)} port(s), {threads} thread(s)")
        print_info("=" * 72)

        results: Dict[str, Dict[int, str]] = {}
        jobs: List[Tuple[str, int]] = [(host, port) for host in targets for port in port_list]

        def probe(job: Tuple[str, int]) -> Tuple[str, int, str]:
            host, port = job
            state = self._probe_port(host, port, timeout)
            return host, port, state

        with ThreadPoolExecutor(max_workers=threads) as pool:
            futures = [pool.submit(probe, job) for job in jobs]
            done = 0
            for future in as_completed(futures):
                host, port, state = future.result()
                done += 1
                if state == "open" or show_closed:
                    results.setdefault(host, {})[port] = state
                if done % max(1, len(jobs) // 10) == 0 or done == len(jobs):
                    print_status(f"Progress: {done}/{len(jobs)} probes")

        open_total = 0
        for host in sorted(results.keys(), key=self._sort_ip):
            ports_map = results[host]
            open_ports = sorted(p for p, state in ports_map.items() if state == "open")
            if not open_ports and not show_closed:
                continue
            open_total += len(open_ports)
            if open_ports:
                print_success(f"{host}: {len(open_ports)} open — {', '.join(str(p) for p in open_ports)}")
            elif show_closed:
                print_info(f"{host}: no open ports in selected range")

        print_info("=" * 72)
        hosts_with_open = sum(1 for h in results if any(s == "open" for s in results[h].values()))
        print_success(
            f"Scan complete: {hosts_with_open} host(s) with open ports, {open_total} open port(s) total"
        )
        saved = self._sync_workspace(results)
        if saved:
            print_info(
                f"Workspace updated: {saved} open port(s) saved — run `campaign --preview` for next steps"
            )
        return bool(open_total)

    def _sync_workspace(self, results: Dict[str, Dict[int, str]]) -> int:
        if not getattr(self, "framework", None):
            return 0
        try:
            from core.workspace_intel import WorkspaceIntelStore

            return WorkspaceIntelStore(self.framework).record_port_scan(
                results,
                source="auxiliary/scanner/portscan/tcp",
            )
        except Exception as exc:
            print_warning(f"Could not update workspace: {exc}")
            return 0

    def _probe_port(self, host: str, port: int, timeout: float) -> str:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            code = sock.connect_ex((host, port))
            sock.close()
            return "open" if code == 0 else "closed"
        except socket.timeout:
            return "filtered"
        except OSError:
            return "closed"
        except Exception:
            return "closed"

    def _parse_targets(self, raw: str) -> List[str]:
        if not raw:
            return []
        hosts: Set[str] = set()
        for chunk in raw.split(","):
            value = chunk.strip()
            if not value:
                continue
            if "-" in value and "/" not in value:
                hosts.update(self._expand_ip_range(value))
                continue
            try:
                if "/" in value:
                    network = ipaddress.ip_network(value, strict=False)
                    hosts.update(str(ip) for ip in network.hosts())
                else:
                    ipaddress.ip_address(value)
                    hosts.add(value)
            except ValueError:
                try:
                    resolved = socket.gethostbyname(value)
                    hosts.add(resolved)
                except Exception:
                    print_warning(f"Skipping invalid target: {value}")
        return sorted(hosts, key=self._sort_ip)

    def _expand_ip_range(self, raw: str) -> List[str]:
        if raw.count("-") != 1:
            return []
        start_raw, end_raw = raw.split("-", 1)
        try:
            start = ipaddress.ip_address(start_raw.strip())
            end_part = end_raw.strip()
            if "." in end_part:
                end = ipaddress.ip_address(end_part)
            else:
                parts = str(start).split(".")
                parts[-1] = end_part
                end = ipaddress.ip_address(".".join(parts))
            if int(end) < int(start):
                start, end = end, start
            return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
        except Exception:
            print_warning(f"Skipping invalid IP range: {raw}")
            return []

    def _parse_ports(self, raw: str) -> List[int]:
        ports: Set[int] = set()
        for chunk in raw.split(","):
            value = chunk.strip()
            if not value:
                continue
            if "-" in value:
                start_s, end_s = value.split("-", 1)
                try:
                    start = int(start_s.strip())
                    end = int(end_s.strip())
                    if start > end:
                        start, end = end, start
                    for port in range(max(1, start), min(65535, end) + 1):
                        ports.add(port)
                except ValueError:
                    print_warning(f"Skipping invalid port range: {value}")
            else:
                try:
                    port = int(value)
                    if 1 <= port <= 65535:
                        ports.add(port)
                except ValueError:
                    print_warning(f"Skipping invalid port: {value}")
        return sorted(ports)

    def _sort_ip(self, value: str) -> Tuple[int, int, int, int]:
        try:
            parts = [int(p) for p in value.split(".")]
            while len(parts) < 4:
                parts.append(0)
            return tuple(parts[:4])  # type: ignore[return-value]
        except Exception:
            return (999, 999, 999, 999)
