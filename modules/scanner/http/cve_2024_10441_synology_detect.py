#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Synology synoplugind pre-auth RCE exposure (CVE-2024-10441 / SA-24:20)."""

import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


def _parse_build(ver: str) -> tuple:
    """Return (major_minor_patch, build) from strings like 7.2.2-72806-1."""
    ver = str(ver or '').strip()
    m = re.match(r'^(\d+(?:\.\d+)*)(?:-(\d+))?', ver)
    if not m:
        return (), 0
    parts = tuple(int(x) for x in m.group(1).split('.'))
    build = int(m.group(2) or 0)
    return parts, build


def _synology_vulnerable(version: str) -> bool:
    parts, build = _parse_build(version)
    if not parts:
        return False
    # Fixed floors from Synology SA-24:20 (DSM); conservative match on major lines.
    fixed = (
        ((7, 2, 2), 72806),
        ((7, 2, 1), 69057),
        ((7, 2), 64570),
        ((7, 1, 1), 42962),
        ((6, 2, 4), 25556),
    )
    for fparts, fbuild in fixed:
        if parts[: len(fparts)] == fparts:
            if len(parts) > len(fparts):
                return True
            return build < fbuild
        if parts > fparts[: len(parts)]:
            continue
        if parts < fparts:
            return True
    if parts[0] >= 7 or (parts[0] == 6 and parts >= (6, 2)):
        return True
    return False


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Synology DSM - synoplugind RCE Exposure (CVE-2024-10441)',
        'description': (
            'Identifies Synology DSM/BeeStation systems whose firmware is below SA-24:20 '
            'fixes for CVE-2024-10441 (pre-auth synoplugind / SYNO.API.Auth plugin env '
            'injection). Uses SYNO.Core.System firmware when available.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'synology', 'dsm', 'nas', 'rce', 'kev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.35,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'scanner/http/synology_dsm_system_info_detect',
                    'scanner/http/synology_rackstation_detect',
                ],
            },
        },
        'references': [
            'https://www.synology.com/en-global/security/advisory/Synology_SA_24_20',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-10441',
        ],
        'cve': 'CVE-2024-10441',
    }

    def _firmware_version(self) -> str:
        paths = (
            '/webapi/entry.cgi?api=SYNO.Core.System&version=3&method=info',
            '/webapi/entry.cgi?api=SYNO.DSM.Info&version=2&method=getinfo',
        )
        for path in paths:
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            try:
                data = r.json()
            except json.JSONDecodeError:
                continue
            for key in ('firmware_ver', 'version_string', 'version'):
                block = data.get('data') if isinstance(data.get('data'), dict) else data
                if isinstance(block, dict):
                    val = block.get(key)
                    if val:
                        return str(val)
        return ''

    def run(self):
        fw = self._firmware_version()
        if not fw:
            r = self.http_request(
                method='GET',
                path='/webapi/entry.cgi?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth',
                allow_redirects=False,
            )
            if r and r.status_code == 200 and 'SYNO.API.Auth' in (r.text or ''):
                self.set_info(
                    severity='high',
                    reason='Synology DSM with SYNO.API.Auth exposed (manual CVE-2024-10441 check)',
                    path='/webapi/entry.cgi',
                )
                return True
            return False
        if _synology_vulnerable(fw):
            self.set_info(
                severity='critical',
                reason=f'Synology firmware {fw} likely vulnerable to CVE-2024-10441',
                path='/webapi/entry.cgi',
            )
            return True
        return False
