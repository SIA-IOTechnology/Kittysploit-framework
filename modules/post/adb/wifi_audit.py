#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Audit Wi-Fi posture on a compromised Android device."""

from __future__ import annotations

import re

from kittysploit import *
from lib.protocols.adb.wifi import AdbWifi


class Module(Post):
    __info__ = {
        "name": "Android WiFi Audit",
        "description": (
            "Audit Android Wi-Fi posture: radio state, current connection, saved "
            "networks, MAC randomization, proxy, and insecure configurations."
        ),
        "author": "KittySploit Team",
        "session_type": SessionType.ANDROID,
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['risk_signals', 'tech_hints', 'endpoints'],
        'cost': 1.5,
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
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    verbose = OptBool(False, "Show additional Wi-Fi diagnostics", required=False)

    def run(self):
        try:
            self._wifi = AdbWifi(cmd_execute=self._cmd)
            print_status("Running Android Wi-Fi audit...")
            print_info("=" * 80)

            self._check_radio_state()
            self._check_current_connection()
            self._check_saved_networks()
            self._check_mac_randomization()
            self._check_proxy_on_wifi()
            self._check_scan_results()

            print_info("=" * 80)
            print_success("Android Wi-Fi audit completed")
            return True
        except Exception as exc:
            print_error(f"Error: {exc}")
            return False

    def _cmd(self, command: str) -> str:
        return (self.cmd_execute(command) or "").strip()

    def _check_radio_state(self):
        print_status("Check: Wi-Fi radio state")
        state = self._wifi.shell("settings get global wifi_on")
        if state == "1":
            print_success("Wi-Fi radio is enabled")
        elif state == "0":
            print_info("Wi-Fi radio is disabled")
        else:
            status = self._wifi.shell("cmd wifi status") or self._wifi.shell("dumpsys wifi | head -40")
            if status and "enabled" in status.lower():
                print_success("Wi-Fi appears enabled")
            elif status and "disabled" in status.lower():
                print_info("Wi-Fi appears disabled")
            else:
                print_warning("Could not determine Wi-Fi radio state")
        print_info("-" * 80)

    def _check_current_connection(self):
        print_status("Check: Current Wi-Fi connection")
        status = self._wifi.fetch_wifi_status()
        if not status:
            print_warning("Could not retrieve Wi-Fi status")
            print_info("-" * 80)
            return

        info = self._wifi.parse_status(status)
        if info.get("ssid"):
            print_info(f"  SSID: {info['ssid']}")
        if info.get("bssid"):
            print_info(f"  BSSID: {info['bssid']}")
        if info.get("security"):
            sec = info["security"]
            if self._wifi.classify_security(sec) == "open":
                print_warning(f"  Security: {sec}")
            else:
                print_success(f"  Security: {sec}")
        if info.get("ip"):
            print_info(f"  IP: {info['ip']}")
        if info.get("frequency"):
            print_info(f"  Frequency: {info['frequency']} MHz")
        if info.get("rssi"):
            print_info(f"  RSSI: {info['rssi']} dBm")

        if not info:
            print_warning("Connected Wi-Fi details not available (permissions or not associated)")
        elif self.verbose:
            for line in status.splitlines()[:60]:
                text = line.strip()
                if text:
                    print_info(f"  {text}")
        print_info("-" * 80)

    def _check_saved_networks(self):
        print_status("Check: Saved networks and security mix")
        networks, source = self._wifi.collect_saved_networks()
        if not networks:
            print_warning("No saved networks enumerated")
            print_info("-" * 80)
            return

        buckets = {"open": 0, "wpa2": 0, "wpa3": 0, "wpa_enterprise": 0, "owe": 0, "other": 0}
        for entry in networks:
            buckets[self._wifi.classify_security(entry.security)] += 1

        print_info(f"  Source: {source}")
        print_info(f"  Total saved: {len(networks)}")
        for name, count in buckets.items():
            if count:
                line = f"  {name}: {count}"
                if name == "open":
                    print_warning(line)
                else:
                    print_info(line)

        if buckets["open"]:
            print_warning("Open saved networks increase auto-connect rogue-AP risk")
        print_info("-" * 80)

    def _check_mac_randomization(self):
        print_status("Check: MAC randomization")
        keys = [
            "wifi_connected_mac_randomization_enabled",
            "wifi_p2p_mac_randomization_enabled",
            "wifi_scan_always_enabled",
        ]
        found = False
        for key in keys:
            value = self._wifi.shell(f"settings get secure {key}")
            if not value or value.lower() == "null":
                continue
            found = True
            label = key.replace("wifi_", "").replace("_", " ")
            if value == "1":
                print_success(f"  {label}: enabled")
            else:
                print_warning(f"  {label}: disabled ({value})")

        if not found:
            mac = self._wifi.shell("cat /sys/class/net/wlan0/address")
            if mac:
                print_info(f"  wlan0 MAC: {mac}")
            print_warning("MAC randomization settings not exposed on this Android build")
        print_info("-" * 80)

    def _check_proxy_on_wifi(self):
        print_status("Check: Proxy while on Wi-Fi")
        http_proxy = self._wifi.shell("settings get global http_proxy")
        host = self._wifi.shell("settings get global global_http_proxy_host")
        port = self._wifi.shell("settings get global global_http_proxy_port")

        found = False
        if http_proxy and http_proxy.lower() not in ("null", ":0"):
            found = True
            print_warning(f"  http_proxy={http_proxy}")
        if host and host.lower() != "null":
            found = True
            port_text = port if port and port.lower() != "null" else "?"
            print_warning(f"  global_http_proxy={host}:{port_text}")

        if not found:
            print_success("No global HTTP proxy configured")
        print_info("-" * 80)

    def _check_scan_results(self):
        print_status("Check: Nearby Wi-Fi scan results")
        scan_out = self._wifi.shell("cmd wifi list-scan-results")
        if not scan_out:
            scan_out = self._wifi.shell("dumpsys wifi | grep -E 'ScanResult|SSID:|BSSID:|Capabilities:'")

        if not scan_out:
            print_warning("Scan results unavailable (Wi-Fi scan permissions or radio off)")
            return

        entries = 0
        open_nearby = 0
        for line in scan_out.splitlines():
            text = line.strip()
            if not text:
                continue
            if re.search(r"\[ESS\]", text) and "WPA" not in text and "WEP" not in text:
                open_nearby += 1
            if text.lower().startswith("bssid:") or re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}", text, re.I):
                entries += 1
                if self.verbose:
                    print_info(f"  {text}")

        if entries:
            print_info(f"  Nearby AP entries observed: ~{entries}")
        if open_nearby:
            print_warning(f"  Nearby open networks (approx): {open_nearby}")
        if not entries and not open_nearby:
            print_info("  Scan output present but could not count AP entries")
        print_info("-" * 80)
