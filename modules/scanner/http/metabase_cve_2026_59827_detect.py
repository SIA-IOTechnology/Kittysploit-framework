#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metabase H2 OTHER column deserialization (CVE-2026-59827)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.response_validation import parse_json_response


_FIXED_VERSIONS = {
    58: (15, 0),
    59: (12, 0),
    60: (6, 3),
    61: (1, 4),
}


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Metabase - H2 Deserialization RCE Detection (CVE-2026-59827)',
        'description': (
            'Detects potentially vulnerable Metabase versions affected by CVE-2026-59827 '
            '(unsafe Java deserialization of H2 OTHER columns in native queries). '
            'Confirms version via /api/session/properties; full exploitation requires '
            'authenticated native-query access to an H2 database.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2026', 'metabase', 'h2', 'java',
            'deserialization', 'authenticated', 'rce', 'vuln',
        ],
        'cve': 'CVE-2026-59827',
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
                'min_params': 0,
                'tech_hints_any': ['metabase'],
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/multi/http/metabase_cve_2026_59827_rce',
                ],
            },
        },
        'references': [
            'https://github.com/metabase/metabase/security/advisories/GHSA-w95f-x9v9-wv36',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-59827',
            'https://www.exploit-db.com/exploits/52680',
        ],
    }

    port = OptPort(3000, 'Metabase HTTP port', True)
    ssl = OptBool(False, 'Use HTTPS', True, advanced=True)

    @staticmethod
    def _parse_version_tag(tag: str) -> tuple[int, int, int] | None:
        raw = str(tag or '').strip().lstrip('vV')
        nums: list[int] = []
        for part in raw.split('.')[:4]:
            digits = ''
            for ch in part:
                if ch.isdigit():
                    digits += ch
                else:
                    break
            if not digits:
                break
            nums.append(int(digits))
        if len(nums) >= 2 and nums[0] == 0:
            if len(nums) >= 4:
                return nums[1], nums[2], nums[3]
            if len(nums) == 3:
                return nums[1], nums[2], 0
            return nums[1], 0, 0
        if len(nums) >= 3:
            return nums[0], nums[1], nums[2]
        if len(nums) == 2:
            return nums[0], nums[1], 0
        return None

    @classmethod
    def _version_is_vulnerable(cls, tag: str) -> bool:
        parsed = cls._parse_version_tag(tag)
        if not parsed:
            return False
        major, minor, patch = parsed
        if major < 58:
            return False
        fixed = _FIXED_VERSIONS.get(major)
        if not fixed:
            return major >= 58
        f_minor, f_patch = fixed
        if minor > f_minor:
            return False
        if minor < f_minor:
            return True
        return patch < f_patch

    def run(self):
        base = (self.path or '/').rstrip('/')
        path = f'{base}/api/session/properties' if base else '/api/session/properties'
        response = self.http_request(method='GET', path=path, allow_redirects=False)
        if not response or int(response.status_code or 0) != 200:
            return False
        body, err = parse_json_response(response)
        if err or not body:
            return False
        tag = (body.get('version') or {}).get('tag', '')
        if not tag or not self._version_is_vulnerable(str(tag)):
            return False
        self.set_info(
            severity='critical',
            reason=(
                f'Metabase {tag} in CVE-2026-59827 affected range '
                '(H2 OTHER deserialization; auth + native query required)'
            ),
            path=path,
        )
        return True
