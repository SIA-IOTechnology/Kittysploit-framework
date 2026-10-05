#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Zammad session fixation RCE surface (CVE-2026-102489)."""

import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zammad CVE-2026-102489 Session Fixation Detect',
        'description': (
            'Detects Zammad helpdesk instances potentially vulnerable to '
            'CVE-2026-102489 (session fixation leading to RCE as the zammad user). '
            'Affects Zammad 6.3.0–6.5.4; chain with CVE-2026-102490 for root LPE.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'cve': ['CVE-2026-102489'],
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2026-102489',
            'https://csirt.divd.nl/CVE-2026-102489',
        ],
        'tags': ['web', 'scanner', 'zammad', 'helpdesk', 'session-fixation', 'rce', 'kev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'chain': {
                'suggested_followups': [
                    'exploits/multi/http/zammad_cve_2026_102489_rce',
                    'scanner/http/zammad_helpdesk_detect',
                ],
            },
        },
    }

    @staticmethod
    def _version_affected(version: str) -> bool | None:
        if not version:
            return None
        match = re.match(r'(\d+)\.(\d+)\.(\d+)', version)
        if not match:
            return None
        major, minor, patch = (int(match.group(i)) for i in range(1, 4))
        if major == 6 and minor >= 3:
            if minor < 5:
                return True
            if minor == 5 and patch <= 4:
                return True
            return False
        if major >= 7:
            return False
        return None

    def run(self):
        for path in ('/', '/api/v1/monitoring_health', '/#login'):
            r = self.http_request(method='GET', path=path, allow_redirects=True)
            if not r:
                continue
            body = (r.text or '').lower()
            headers = '\n'.join(f'{k}: {v}' for k, v in r.headers.items()).lower()
            if 'zammad' not in body and 'zammad' not in headers:
                continue
            version = ''
            health = self.http_request(method='GET', path='/api/v1/monitoring_health', allow_redirects=False)
            if health and health.status_code == 200:
                try:
                    version = str(json.loads(health.text or '{}').get('version') or '')
                except json.JSONDecodeError:
                    pass
            affected = self._version_affected(version)
            if affected is False:
                return False
            self.set_info(
                severity='critical',
                cve='CVE-2026-102489',
                reason=(
                    f'Zammad {version} in affected 6.3–6.5.4 range'
                    if affected
                    else 'Zammad detected — session fixation surface may exist'
                ),
                version=version or 'unknown',
            )
            return True
        return False
