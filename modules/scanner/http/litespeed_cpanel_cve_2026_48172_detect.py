#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect LiteSpeed cPanel plugin privesc surface (CVE-2026-48172)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LiteSpeed cPanel Plugin CVE-2026-48172 Detection',
        'description': (
            'Detects LiteSpeed Web Server cPanel plugin endpoints that may be '
            'vulnerable to CVE-2026-48172 (Redis enable/disable privesc to root).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'cve': 'CVE-2026-48172',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2026-48172'],
        'tags': ['web', 'scanner', 'cpanel', 'litespeed', 'privesc', 'redis'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals'],
            'chain': {
                'suggested_followups': ['exploits/linux/http/litespeed_cpanel_cve_2026_48172_rce'],
            },
        },
    }

    port = OptPort(2083, 'cPanel HTTPS port', required=False)
    ssl = OptBool(True, 'Use HTTPS', required=False)

    CPANEL_PATHS = (
        '/frontend/jupiter/lsws/index.html',
        '/cpsess0000000000/frontend/jupiter/lsws/index.html',
        '/3rdparty/litespeed/cgi/lsapi.cgi',
    )

    def run(self):
        for path in self.CPANEL_PATHS:
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r:
                continue
            body = (r.text or '').lower()
            if any(m in body for m in ('litespeed', 'lsws', 'redis', 'cpanel_jsonapi')):
                probe = self.http_request(
                    method='GET',
                    path=path,
                    params={'cpanel_jsonapi_func': 'redisAble', 'cpanel_jsonapi_module': 'lsws'},
                    allow_redirects=False,
                )
                if probe and probe.status_code in (200, 401, 403):
                    self.set_info(
                        severity='critical',
                        reason='LiteSpeed cPanel Redis API endpoint exposed (CVE-2026-48172 surface)',
                        path=path,
                        cve='CVE-2026-48172',
                    )
                    return True
        return False
