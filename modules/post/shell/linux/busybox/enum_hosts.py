#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Ported from Metasploit post/linux/busybox/enum_hosts (Msf::Post::Linux::BusyBox).
# Original author: Javier Vicente Vallejo — https://github.com/rapid7/metasploit-framework

import os
import re

from kittysploit import *
from lib.post.linux.system import System
from lib.post.linux.session import LinuxSessionMixin


class Module(Post, System, LinuxSessionMixin):
    __info__ = {
        "name": "BusyBox Enumerate Host Names",
        "description": (
            "For a session on an embedded BusyBox-style Linux shell, enumerate host names from "
            "common router/udhcpd paths: /var/hosts or /var/udhcpd/udhcpd.leases."
        ),
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [
            SessionType.SHELL,
            SessionType.METERPRETER,
            SessionType.SSH,
        ],
        "references": [],
    'agent': {
        'risk': 'intrusive',
        'effects': ['active_exploitation'],
        'expected_requests': 2,
        'reversible': False,
        'approval_required': True,
        'produces': ['risk_signals'],
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'ot_assets', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    _HOSTS_CANDIDATES = ("/var/hosts", "/var/udhcpd/udhcpd.leases")

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

        print_status("Searching hosts files...")
        hosts_file = None
        for path in self._HOSTS_CANDIDATES:
            if self.file_exist(path):
                hosts_file = path
                break

        if not hosts_file:
            print_error("Files not found")
            return False

        return self._read_hosts_file(hosts_file)

    def _read_hosts_file(self, file_path: str) -> bool:
        try:
            content = self.read_file(file_path)
        except Exception as e:
            print_error(f"Failed to read file: {file_path} ({e})")
            return False

        print_success(f"Hosts file found: {file_path}.")
        print_debug(content)

        if content is None or not str(content).strip():
            print_error(f"Nothing read from file: {file_path}, file may be empty.")
            return False

        text = str(content)
        safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", file_path.strip("/").replace("/", "_"))
        out_rel = os.path.join("loot", f"busybox_enum_hosts_{safe}.txt")
        return bool(self.write_out_dir(out_rel, text))
