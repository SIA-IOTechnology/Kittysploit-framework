#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Roundcube webmail."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Roundcube webmail Detection',
        'description': 'Detects Roundcube webmail.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'roundcube', 'portal', 'tech'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
    }

    def run(self):
        # Prefer concrete panel paths first. Matching the homepage with a bare
        # "roundcube" string is a common false positive on WordPress blogs.
        panel_paths = (
            "/webmail/",
            "/webmail",
            "/roundcube/",
            "/roundcube",
            "/mail/",
            "/mail",
            "/rc/",
            "/roundcubemail/",
        )
        strong_regexes = (
            r'"rcversion":\d{3,}',
            r"(?i)rcmloginuser",
            r"(?i)roundcubemail",
            r"(?i)_task=login",
            r"(?i)_task=mail",
        )
        weak_name = re.compile(r"(?i)\broundcube\b")

        for path in panel_paths:
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or int(getattr(r, "status_code", 0) or 0) >= 400:
                continue
            body = r.text or ""
            if any(re.search(rx, body) for rx in strong_regexes) or weak_name.search(body):
                self.set_info(
                    severity='info',
                    reason="Roundcube webmail detected",
                    path=path,
                )
                return True

        # Root only with strong markers (never a lone "roundcube" word).
        r = self.http_request(method="GET", path="/", allow_redirects=True)
        if r and int(getattr(r, "status_code", 0) or 0) < 400:
            body = r.text or ""
            if any(re.search(rx, body) for rx in strong_regexes):
                self.set_info(
                    severity='info',
                    reason="Roundcube webmail detected",
                    path="/",
                )
                return True
        return False

