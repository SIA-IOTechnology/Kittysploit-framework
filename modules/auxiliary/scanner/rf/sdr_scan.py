#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect RTL-SDR dongles and run a quick RF power sweep when tools are available."""

from __future__ import annotations

import csv
import os
import re
import shutil
import subprocess
import tempfile
from typing import Dict, List, Tuple

from kittysploit import *


_KNOWN_SDR_USB = (
    ("0bda:2838", "Realtek RTL2838 DVB-T (RTL-SDR)"),
    ("0bda:2832", "Realtek RTL2832U"),
    ("1d50:6089", "Great Scott Gadgets HackRF One"),
    ("1fc9:8030", "NooElec NESDR"),
    ("1d50:604b", "OpenMoko Mosquito"),
)


class Module(Auxiliary):
    __info__ = {
        "name": "RF SDR Discovery",
        "description": (
            "Detect software-defined radio USB devices and optionally run a quick "
            "spectrum sweep with rtl_power when rtl-sdr tools are installed."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "rf", "sdr", "rtl-sdr", "spectrum", "discovery"],
        "references": [
            "https://attack.mitre.org/techniques/T1016/",
        ],
        "attack": {
            "tactics": ["TA0007", "Discovery"],
            "techniques": ["T1016"],
            "prerequisites": [
                "RTL-SDR or compatible USB receiver (optional for USB detection only)",
                "rtl-sdr package for spectrum sweep (rtl_power, rtl_test)",
            ],
            "detections": [
                "Local RF spectrum sampling on operator host",
            ],
            "artifacts": [
                "Temporary CSV spectrum files on operator host",
            ],
        },
    'agent': {
        'risk': '',
        'effects': ['wireless_sniff'],
        'expected_requests': 1,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints'],
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

    freq_range = OptString(
        "88M:108M:200k",
        "rtl_power frequency range start:stop:step (e.g. 2400M:2500M:200k)",
        required=False,
    )
    integration = OptInteger(1, "rtl_power integration interval in seconds", required=False)
    top_n = OptInteger(10, "Number of strongest peaks to display", required=False)
    skip_sweep = OptBool(False, "Only detect USB devices, skip rtl_power sweep", required=False)

    def check(self):
        if shutil.which("lsusb") or shutil.which("rtl_test") or shutil.which("rtl_power"):
            return True
        print_warning("lsusb and rtl-sdr tools not found — USB detection may be limited")
        return True

    def run(self):
        print_info("RF / SDR discovery")
        print_info("=" * 72)

        usb_devices = self._detect_usb_sdr()
        if usb_devices:
            print_success(f"Detected {len(usb_devices)} potential SDR USB device(s)")
            for entry in usb_devices:
                print_info(f"  {entry['id']} — {entry['name']}")
        else:
            print_warning("No known SDR USB devices detected via lsusb")

        if bool(self.skip_sweep):
            print_info("Spectrum sweep skipped (SKIP_SWEEP=true)")
            return bool(usb_devices)

        if not shutil.which("rtl_power"):
            print_warning("rtl_power not installed — install rtl-sdr package for spectrum sweep")
            if shutil.which("rtl_test"):
                self._run_rtl_test()
            return bool(usb_devices)

        peaks = self._run_rtl_power_sweep()
        print_info("=" * 72)
        if peaks:
            print_success(f"Top {len(peaks)} RF peaks in {self.freq_range}")
            for freq_mhz, power in peaks:
                print_info(f"  {freq_mhz:10.3f} MHz  {power:6.1f} dB")
            return True

        print_warning("Spectrum sweep produced no results — check dongle permissions and gain")
        return bool(usb_devices)

    def _detect_usb_sdr(self) -> List[Dict[str, str]]:
        if not shutil.which("lsusb"):
            return []
        proc = subprocess.run(
            ["lsusb"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        found: List[Dict[str, str]] = []
        for line in proc.stdout.splitlines():
            match = re.search(r"ID ([0-9a-f]{4}:[0-9a-f]{4})", line, flags=re.IGNORECASE)
            if not match:
                continue
            usb_id = match.group(1).lower()
            for known_id, label in _KNOWN_SDR_USB:
                if usb_id == known_id:
                    found.append({"id": usb_id, "name": label, "line": line.strip()})
                    print_success(f"USB SDR: {label} ({usb_id})")
                    break
        return found

    def _run_rtl_test(self) -> None:
        print_status("Running rtl_test (dongle check)...")
        proc = subprocess.run(
            ["rtl_test", "-t"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
        for line in output.splitlines()[:20]:
            text = line.strip()
            if text:
                print_info(f"  {text}")

    def _run_rtl_power_sweep(self) -> List[Tuple[float, float]]:
        freq_range = str(self.freq_range or "88M:108M:200k").strip()
        integration = max(1, int(self.integration or 1))
        top_n = max(1, int(self.top_n or 10))

        with tempfile.NamedTemporaryFile(prefix="ks_rtl_", suffix=".csv", delete=False) as tmp:
            csv_path = tmp.name

        print_status(f"Running rtl_power on {freq_range} (integration {integration}s)...")
        try:
            proc = subprocess.run(
                [
                    "rtl_power",
                    "-f",
                    freq_range,
                    "-i",
                    str(integration),
                    "-1",
                    csv_path,
                ],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            if proc.returncode != 0 and not os.path.exists(csv_path):
                raise RuntimeError((proc.stderr or proc.stdout or "rtl_power failed").strip())
            return self._parse_rtl_power_csv(csv_path, top_n)
        finally:
            try:
                os.unlink(csv_path)
            except OSError:
                pass

    def _parse_rtl_power_csv(self, path: str, top_n: int) -> List[Tuple[float, float]]:
        peaks: List[Tuple[float, float]] = []
        with open(path, newline="", encoding="utf-8", errors="ignore") as handle:
            reader = csv.reader(handle)
            for row in reader:
                if len(row) < 7:
                    continue
                try:
                    hz_low = float(row[2])
                    hz_high = float(row[3])
                    db_values = [float(v) for v in row[6:]]
                except ValueError:
                    continue
                if not db_values:
                    continue
                step = (hz_high - hz_low) / len(db_values)
                for index, power in enumerate(db_values):
                    freq_hz = hz_low + (index * step)
                    peaks.append((freq_hz / 1_000_000.0, power))

        peaks.sort(key=lambda item: item[1], reverse=True)
        return peaks[:top_n]
