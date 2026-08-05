#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client


# Paths to probe; (path, validator). Validator: None = any 200, or callable(response) -> bool
SENSITIVE_PATHS = [
    (".env", lambda r: "=" in r.text or "secret" in r.text.lower() or "password" in r.text.lower()),
    (".env.backup", None),
    (".env.old", None),
    (".env.local", None),
    (".git/HEAD", lambda r: "ref:" in r.text),
    (".git/config", lambda r: "[core]" in r.text or "[" in r.text),
    (".gitignore", None),
    ("backup.sql", None),
    ("db.sql", None),
    ("database.sql", None),
    (".htaccess", lambda r: "rewrite" in r.text.lower() or "deny" in r.text.lower() or "allow" in r.text.lower()),
    ("web.config", lambda r: "<" in r.text and "configuration" in r.text.lower()),
    ("config.bak", None),
    ("config.php.bak", None),
    ("wp-config.php.bak", None),
    (".DS_Store", None),
    ("phpinfo.php", lambda r: "phpinfo" in r.text.lower() or "php version" in r.text.lower()),
    ("debug.log", None),
    ("composer.json", lambda r: "require" in r.text and "{" in r.text)]


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Sensitive files detection',
        'description': 'Detects exposed sensitive files (.env, .git, backups, config, etc.).',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'modules': [],
        'tags': ['web', 'scanner', 'sensitive', 'disclosure', 'backup', '.env', '.git'],
    'agent': {
        'risk': 'active',
        'effects': ['network_probe'],
        'expected_requests': 2,
        'reversible': True,
        'approval_required': False,
        'produces': ['tech_hints', 'risk_signals', 'endpoints'],
        'cost': 1.0,
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
        'chain':         {'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    def run(self):
        found = []
        for path, validator in SENSITIVE_PATHS:
            path = path if path.startswith("/") else "/" + path
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            # Catch-all / SPA hosts often return the homepage for every path.
            if self.is_same_as_index(r, path=path):
                continue
            if validator is None:
                # Without a content validator, require body to differ from empty/HTML index.
                body = (r.text or "").strip()
                if not body or self.is_same_as_index(r, path=path):
                    continue
                # Generic 200 with no validator: only keep non-HTML binary/text clues
                low = body[:200].lower()
                if "<html" in low or "<!doctype" in low:
                    continue
                found.append(path.lstrip("/"))
                continue
            if validator(r) and not self.is_same_as_index(r, path=path):
                # Validators must still reject HTML clones of the index.
                body = (r.text or "").lower()
                if path.endswith(".git/config") and "[core]" not in body and "[credentials]" not in body:
                    continue
                found.append(path.lstrip("/"))
        if found:
            self.set_info(severity="low", reason=f"Exposed: {', '.join(found)}")
            return True
        return False
