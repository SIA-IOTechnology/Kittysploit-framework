#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects vBulletin - Full Path Disclosure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'vBulletin - Full Path Disclosure Detection',
        'description': 'Detects vBulletin - Full Path Disclosure.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'config', 'fpd', 'vbulletin', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
        'references': ['https://github.com/OWASP/vbscan/blob/master/modules/pathdisclure.pl'],
    }

    def run(self):
        for path in ('/', '/forumdisplay.php?do[]=[test.dll]', '/calendar.php?do[]=[test.dll]', '/search.php?do[]=[test.dll]', '/forumrunner/include/album.php', '/core/vb5/route/channel.php', '/core/vb5/route/conversation.php', '/includes/api/interface/noncollapsed.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('vBulletin', '<strong>Warning</strong>:', 'Cannot modify header information', '/strong> on line', 'trim() expects parameter', 'class_core.php', 'header already sent', 'Fatal error',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='info',
                    reason="vBulletin - Full Path Disclosure detected",
                    path=path,
                )
                return True
        return False

