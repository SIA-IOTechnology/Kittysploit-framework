#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect GitHub Enterprise Server push-option RCE surface (CVE-2026-3854)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GitHub Enterprise Server CVE-2026-3854 Detection',
        'description': (
            'Detects GitHub Enterprise Server instances potentially vulnerable to '
            'CVE-2026-3854 (push option header injection leading to RCE). '
            'Checks GHES fingerprint and git push option endpoint behaviour.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'cve': 'CVE-2026-3854',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2026-3854'],
        'tags': ['web', 'scanner', 'github', 'ghes', 'rce', 'git'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'chain': {
                'suggested_followups': ['exploits/multi/http/ghes_cve_2026_3854_rce'],
            },
        },
    }

    def run(self):
        for path in ('/login', '/api/v3/meta', '/setup/settings'):
            r = self.http_request(method='GET', path=path, allow_redirects=True)
            if not r or r.status_code not in (200, 302):
                continue
            body = (r.text or '').lower()
            headers = '\n'.join(f'{k}: {v}' for k, v in r.headers.items()).lower()
            if 'github enterprise' in body or 'x-github-enterprise-version' in headers:
                version = r.headers.get('X-GitHub-Enterprise-Version', '')
                self.set_info(
                    severity='critical',
                    reason='GitHub Enterprise Server detected — check CVE-2026-3854 patch level',
                    path=path,
                    cve='CVE-2026-3854',
                    version=version or 'unknown',
                )
                return True
        return False
