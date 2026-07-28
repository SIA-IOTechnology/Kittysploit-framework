#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected PHP versions that have reached End-of-Life (EOL) and no longer receive security updates."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHP End-of-Life - Detect',
        'description': 'Detected PHP versions that have reached End-of-Life (EOL) and no longer receive security updates.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'php', 'eol'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
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
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://www.php.net/supported-versions.php', 'https://endoflife.date/php'],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        # Need an actual PHP version banner, not any header containing "php".
        import re
        serverish = "\n".join(
            f"{k}: {v}" for k, v in r.headers.items()
            if k.lower() in {"server", "x-powered-by", "x-generator"}
        )
        match = re.search(r'php[/\s]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', serverish, re.I)
        if not match:
            return False
        major_minor = match.group(1)
        parts = [int(x) for x in major_minor.split(".")[:2]]
        major, minor = parts[0], parts[1] if len(parts) > 1 else 0
        # PHP < 8.1 is EOL as of 2026 (adjust as support matrix evolves).
        if (major, minor) >= (8, 1):
            return False
        self.set_info(
            severity='info',
            reason=f'PHP End-of-Life version disclosed ({major_minor})',
            path=path,
            version=major_minor,
        )
        return True

