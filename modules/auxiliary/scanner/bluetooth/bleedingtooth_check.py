#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BleedingTooth exposure check — local Linux kernel Bluetooth stack assessment.

Detection only (no exploit). Maps local kernel + Bluetooth HCI state against
the BleedingTooth family (CVE-2020-12351/12352/24490).

Note: distribution backports can patch older version strings; treat results as
heuristic unless the host is confirmed unpatched.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from kittysploit import *


# Heuristic fixed floors (mainline). Distro kernels may backport earlier.
# See: https://google.github.io/security-research/pocs/linux/bleedingtooth/writeup.html
CVE_CATALOG = [
    {
        "id": "CVE-2020-12351",
        "name": "BadKarma",
        "severity": "HIGH",
        "summary": "A2MP/L2CAP type confusion — DoS or potential RCE in range",
        # Introduced ~4.8; fixed mainline ~5.9 / LTS backports
        "introduced": (4, 8, 0),
        "fixed_mainline": (5, 9, 0),
        "fixed_lts": {
            (4, 19): (4, 19, 152),
            (5, 4): (5, 4, 72),
        },
    },
    {
        "id": "CVE-2020-12352",
        "name": "BadChoice",
        "severity": "MEDIUM",
        "summary": "AMP packet stack info leak — KASLR defeat / secret leak",
        "introduced": (3, 6, 0),
        "fixed_mainline": (5, 9, 0),
        "fixed_lts": {
            (4, 19): (4, 19, 152),
            (5, 4): (5, 4, 72),
            (4, 14): (4, 14, 202),
            (4, 9): (4, 9, 240),
            (4, 4): (4, 4, 240),
        },
    },
    {
        "id": "CVE-2020-24490",
        "name": "BadVibes",
        "severity": "MEDIUM",
        "summary": "Extended advertising report heap overflow — DoS / potential RCE",
        "introduced": (4, 19, 0),
        "fixed_mainline": (5, 9, 0),
        "fixed_lts": {
            (4, 19): (4, 19, 152),
            (5, 4): (5, 4, 72),
        },
    },
]

BT_MODULE_HINTS = (
    "bluetooth",
    "btusb",
    "btintel",
    "btrtl",
    "btbcm",
    "bnep",
    "rfcomm",
    "hidp",
)


class Module(Auxiliary):
    __info__ = {
        "name": "BleedingTooth Check",
        "description": (
            "Assesses local Linux Bluetooth/kernel exposure to the BleedingTooth "
            "family (CVE-2020-12351 BadKarma, CVE-2020-12352 BadChoice, "
            "CVE-2020-24490 BadVibes). Detection only — no exploit payload."
        ),
        "author": ["KittySploit Team"],
        "version": "1.0.0",
        "tags": [
            "scanner",
            "bluetooth",
            "bleedingtooth",
            "kernel",
            "cve",
            "wireless",
            "linux",
        ],
        "references": [
            "https://google.github.io/security-research/pocs/linux/bleedingtooth/writeup.html",
            "https://access.redhat.com/security/vulnerabilities/BleedingTooth",
            "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00435.html",
            "CVE-2020-12351",
            "CVE-2020-12352",
            "CVE-2020-24490",
        ],
        "attack": {
            "tactics": ["TA0007", "Discovery"],
            "techniques": ["T1016", "T1592"],
            "prerequisites": [
                "Linux host (local assessment)",
                "Optional: Bluetooth HCI adapter present",
            ],
            "detections": [
                "Local kernel/module enumeration — no RF exploit traffic",
            ],
            "artifacts": [
                "Optional JSON report on operator host",
            ],
        },
        "agent": {
            "risk": "passive",
            "effects": ["recon"],
            "expected_requests": 0,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "tech_hints"],
            "cost": 0.3,
            "noise": 0.0,
            "value": 1.2,
            "chain": {
                "produces_capabilities": [
                    {"capability": "bt_kernel_risk", "from_detail": "bleedingtooth"},
                ],
                "suggested_followups": [
                    "auxiliary/scanner/bluetooth/ble_scan",
                    "auxiliary/scanner/bluetooth/classic_scan",
                ],
            },
        },
    }

    hci = OptString("hci0", "Preferred HCI device name for status checks", False)
    export_json = OptString("", "Optional JSON report path", False)
    assume_unpatched = OptBool(
        False,
        "Ignore possible distro backports — treat version heuristic as definitive",
        False,
    )

    def check(self):
        if platform.system().lower() != "linux":
            print_error("BleedingTooth check targets Linux hosts only")
            return False
        return True

    def run(self):
        print_info("=" * 80)
        print_success("BleedingTooth exposure check (detection only)")
        print_info("=" * 80)

        kernel_raw, kernel_tuple = self._kernel_version()
        modules = self._loaded_bt_modules()
        hci_devices = self._list_hci_devices()
        hci_up = self._hci_is_up(str(self.hci or "hci0"), hci_devices)
        bluez = self._bluez_version()

        print_info(f"Kernel     : {kernel_raw or 'unknown'}")
        print_info(f"BlueZ      : {bluez or 'not detected'}")
        print_info(f"BT modules : {', '.join(modules) if modules else 'none loaded'}")
        print_info(
            f"HCI devices: {', '.join(hci_devices) if hci_devices else 'none'} "
            f"(preferred {self.hci} up={hci_up})"
        )

        if not kernel_tuple:
            print_error("Could not parse kernel version")
            return False

        findings = []
        for cve in CVE_CATALOG:
            status = self._assess_cve(kernel_tuple, cve)
            findings.append(status)

        print_info("-" * 80)
        exposed = [f for f in findings if f["status"] == "potentially_vulnerable"]
        patched = [f for f in findings if f["status"] == "likely_patched"]
        not_applicable = [f for f in findings if f["status"] == "not_applicable"]

        for item in findings:
            line = (
                f"{item['id']} ({item['name']}) [{item['severity']}] — {item['status']}"
            )
            if item["status"] == "potentially_vulnerable":
                print_warning(line)
            elif item["status"] == "likely_patched":
                print_success(line)
            else:
                print_info(line)
            print_info(f"    {item['summary']}")
            print_info(f"    reason: {item['reason']}")

        bluetooth_attack_surface = bool(modules) or bool(hci_devices)
        risk = "low"
        if exposed and bluetooth_attack_surface:
            risk = "high" if any(f["severity"] == "HIGH" for f in exposed) else "medium"
        elif exposed and not bluetooth_attack_surface:
            risk = "medium"
            print_warning(
                "Kernel version looks vulnerable but no Bluetooth modules/HCI seen "
                "(reduced practical exposure)"
            )

        print_info("-" * 80)
        if exposed and bluetooth_attack_surface:
            print_warning(
                f"Host appears EXPOSED to {len(exposed)} BleedingTooth CVE(s) "
                f"with Bluetooth stack present (risk={risk})"
            )
        elif exposed:
            print_warning(
                f"Kernel version matches {len(exposed)} CVE range(s) but BT may be inactive "
                f"(risk={risk})"
            )
        else:
            print_success("No BleedingTooth CVE ranges matched for this kernel heuristic")

        if not bool(self.assume_unpatched):
            print_info(
                "Note: distro kernels often backport fixes — verify with vendor advisory "
                "before treating as confirmed vulnerable"
            )

        print_info("Mitigations if unpatched and BT not required:")
        print_info("  - rfkill block bluetooth")
        print_info("  - systemctl stop bluetooth; modprobe -r btusb bluetooth")
        print_info("  - upgrade kernel to a patched release and reboot")

        report = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "detection_only": True,
            "kernel": kernel_raw,
            "kernel_tuple": list(kernel_tuple) if kernel_tuple else None,
            "bluez": bluez,
            "bt_modules": modules,
            "hci_devices": hci_devices,
            "hci_preferred_up": hci_up,
            "bluetooth_attack_surface": bluetooth_attack_surface,
            "assume_unpatched": bool(self.assume_unpatched),
            "risk": risk,
            "findings": findings,
            "summary": {
                "potentially_vulnerable": [f["id"] for f in exposed],
                "likely_patched": [f["id"] for f in patched],
                "not_applicable": [f["id"] for f in not_applicable],
            },
        }

        out = str(self.export_json or "").strip()
        if out:
            try:
                with open(out, "w", encoding="utf-8") as handle:
                    json.dump(report, handle, indent=2)
                print_success(f"Report written to {out}")
            except OSError as exc:
                print_error(f"Failed to write report: {exc}")

        # Auxiliary convention: True = check completed (not necessarily "vuln found")
        return True

    # --- helpers ---

    def _kernel_version(self) -> Tuple[str, Optional[Tuple[int, int, int]]]:
        raw = platform.release() or ""
        try:
            out = subprocess.check_output(["uname", "-r"], text=True, stderr=subprocess.DEVNULL).strip()
            if out:
                raw = out
        except Exception:
            pass
        return raw, self._parse_version(raw)

    def _parse_version(self, text: str) -> Optional[Tuple[int, int, int]]:
        match = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", str(text or ""))
        if not match:
            return None
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3) or 0)
        return (major, minor, patch)

    def _version_ge(self, current: Tuple[int, int, int], minimum: Tuple[int, int, int]) -> bool:
        return current >= minimum

    def _assess_cve(self, kernel: Tuple[int, int, int], cve: Dict) -> Dict:
        introduced = cve["introduced"]
        fixed_mainline = cve["fixed_mainline"]
        fixed_lts = cve.get("fixed_lts") or {}

        if kernel < introduced:
            return {
                "id": cve["id"],
                "name": cve["name"],
                "severity": cve["severity"],
                "summary": cve["summary"],
                "status": "not_applicable",
                "reason": f"kernel {kernel} older than introduction {introduced}",
            }

        # Exact LTS branch match (major.minor)
        branch = (kernel[0], kernel[1])
        if branch in fixed_lts:
            floor = fixed_lts[branch]
            if self._version_ge(kernel, floor):
                return {
                    "id": cve["id"],
                    "name": cve["name"],
                    "severity": cve["severity"],
                    "summary": cve["summary"],
                    "status": "likely_patched",
                    "reason": f"LTS branch {branch[0]}.{branch[1]} >= fixed {floor[0]}.{floor[1]}.{floor[2]}",
                }
            return {
                "id": cve["id"],
                "name": cve["name"],
                "severity": cve["severity"],
                "summary": cve["summary"],
                "status": "potentially_vulnerable",
                "reason": f"LTS branch {branch[0]}.{branch[1]} < fixed {floor[0]}.{floor[1]}.{floor[2]}",
            }

        if self._version_ge(kernel, fixed_mainline):
            return {
                "id": cve["id"],
                "name": cve["name"],
                "severity": cve["severity"],
                "summary": cve["summary"],
                "status": "likely_patched",
                "reason": f"kernel >= mainline fix {fixed_mainline[0]}.{fixed_mainline[1]}",
            }

        suffix = ""
        if not bool(self.assume_unpatched):
            suffix = " (confirm distro backports)"
        return {
            "id": cve["id"],
            "name": cve["name"],
            "severity": cve["severity"],
            "summary": cve["summary"],
            "status": "potentially_vulnerable",
            "reason": f"kernel {kernel} < mainline fix {fixed_mainline[0]}.{fixed_mainline[1]}{suffix}",
        }

    def _loaded_bt_modules(self) -> List[str]:
        found = []
        path = "/proc/modules"
        if not os.path.isfile(path):
            return found
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                text = handle.read().lower()
            for name in BT_MODULE_HINTS:
                if re.search(rf"^{re.escape(name)}\s", text, re.M) or f" {name} " in f" {text} ":
                    # more precise: line start
                    if any(line.startswith(name + " ") for line in text.splitlines()):
                        found.append(name)
        except OSError:
            pass
        return found

    def _list_hci_devices(self) -> List[str]:
        devices = []
        sys_path = "/sys/class/bluetooth"
        if os.path.isdir(sys_path):
            try:
                devices = sorted(
                    name
                    for name in os.listdir(sys_path)
                    if re.fullmatch(r"hci\d+", name)
                )
            except OSError:
                pass
        if devices:
            return devices
        # Fallback hciconfig
        if shutil.which("hciconfig"):
            try:
                out = subprocess.check_output(
                    ["hciconfig"], text=True, stderr=subprocess.DEVNULL, timeout=5
                )
                devices = re.findall(r"^(hci\d+):", out, re.M)
            except Exception:
                pass
        return devices

    def _hci_is_up(self, preferred: str, devices: List[str]) -> bool:
        target = preferred if preferred in devices else (devices[0] if devices else preferred)
        if shutil.which("hciconfig") and target:
            try:
                out = subprocess.check_output(
                    ["hciconfig", target], text=True, stderr=subprocess.DEVNULL, timeout=5
                )
                return "UP RUNNING" in out or "\n\tUP " in out or "UP " in out
            except Exception:
                pass
        if shutil.which("bluetoothctl"):
            try:
                out = subprocess.check_output(
                    ["bluetoothctl", "show"], text=True, stderr=subprocess.DEVNULL, timeout=5
                )
                return "Powered: yes" in out
            except Exception:
                pass
        return bool(devices)

    def _bluez_version(self) -> str:
        for cmd in (("bluetoothctl", "--version"), ("bluetoothd", "-v")):
            if not shutil.which(cmd[0]):
                continue
            try:
                out = subprocess.check_output(
                    list(cmd), text=True, stderr=subprocess.STDOUT, timeout=5
                ).strip()
                if out:
                    return out.splitlines()[0].strip()
            except Exception:
                continue
        return ""
