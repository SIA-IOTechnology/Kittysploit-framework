#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grafana instances up to 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Grafana Snapshot - Authentication Bypass Detection',
        'description': 'Grafana instances up to 7.5.11 and 8.1.5 allow remote unauthenticated users to view the snapshot associated with the lowest database key by accessing the literal paths /api/snapshot/:key or /dashboard/snapshot/:key. If the snapshot is in public mode, unauthenticated users can delete snapshots by accessing the endpoint /api/snapshots-delete/:deleteKey. Authenticated users can also delete snapshots by accessing the endpoints /api/snapshots-delete/:deleteKey, or sending a delete request to /api/snapshot/:key, regardless of whether or not the snapshot is set to public mode (disabled by default).',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'grafana', 'kev', 'vkev', 'vuln'],
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
        'references': [
            'https://github.com/advisories/GHSA-69j6-29vr-p3j9',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-39226',
            'https://github.com/grafana/grafana/commit/2d456a6375855364d098ede379438bf7f0667269',
            'https://grafana.com/docs/grafana/latest/release-notes/release-notes-8-1-6/',
            'http://www.openwall.com/lists/oss-security/2021/10/05/4',
        ],
        'cve': 'CVE-2021-39226',
    }

    def run(self):
        for path in ('/api/snapshots/:key', '/dashboard/snapshot/:key'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('"isSnapshot":true',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="Grafana Snapshot - Authentication Bypass detected",
                    path=path,
                )
                return True
        return False

