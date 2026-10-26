#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect PHP2Shell exposure (CVE-2026-109618 / CVE-2026-109619)."""

from __future__ import annotations

import re
from typing import Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.detectors import detect_php

_PATCHED = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHP2Shell (CVE-2026-109618/619) detection',
        'description': (
            'Flags PHP versions in the CVE-2026-109618 / CVE-2026-109619 affected ranges. '
            'Confirm exploitation with exploits/multi/http/php2shell_cve_2026_109618_rce.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'cve': ['CVE-2026-109618', 'CVE-2026-109619'],
        'references': [
            'https://github.com/NCSC-NL/php2shell',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-109618',
        ],
        'modules': ['exploits/multi/http/php2shell_cve_2026_109618_rce'],
        'tags': ['web', 'scanner', 'php', 'php2shell', 'rce', 'cve-2026-109618'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.2,
            'value': 1.0,
            'requires': {'tech_hints_any': ['php']},
            'chain': {
                'produces_capabilities': [{'capability': 'rce_surface', 'from_detail': 'php2shell'}],
                'suggested_followups': ['exploits/multi/http/php2shell_cve_2026_109618_rce'],
            },
        },
    }

    target_path = OptString('/index.php', 'PHP entrypoint path', required=False)

    @staticmethod
    def _version_tuple(version: str) -> Tuple[int, ...]:
        parts: list[int] = []
        for token in re.findall(r'\d+', version or ''):
            parts.append(int(token))
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:3])

    def _is_vulnerable_version(self, version: str) -> Optional[bool]:
        major, minor, patch = self._version_tuple(version)
        if major == 0:
            return None
        if (major, minor) < (8, 2):
            return True
        floor = _PATCHED.get((major, minor))
        if not floor:
            return None
        return (major, minor, patch) < floor

    def run(self):
        try:
            path = str(self.target_path or '/index.php').strip()
            if not path.startswith('/'):
                path = f'/{path}'
            response = self.http_request(method='GET', path=path, allow_redirects=True, timeout=15)
            if not response:
                return False

            version = detect_php(response) or ''
            if not version:
                blob = ' '.join(f'{k}:{v}' for k, v in response.headers.items())
                match = re.search(r'PHP/([\d.]+)', blob, re.I)
                version = match.group(1) if match else ''

            vuln = self._is_vulnerable_version(version) if version else None
            server = response.headers.get('Server', '')

            if vuln is True:
                self.set_info(
                    severity='critical',
                    cve='CVE-2026-109618',
                    reason=f'PHP {version} at {path} is in the PHP2Shell affected range',
                    version=version,
                    path=path,
                    server=server,
                    confidence='high',
                )
                return True

            if vuln is False:
                self.set_info(
                    severity='info',
                    reason=f'PHP {version} at {path} appears patched for PHP2Shell',
                    version=version,
                    path=path,
                )
                return False

            if 'php' in (server + str(response.headers)).lower():
                self.set_info(
                    severity='medium',
                    cve='CVE-2026-109618',
                    reason=f'PHP detected at {path} but version unknown',
                    path=path,
                    confidence='low',
                )
                return True
            return False
        except Exception:
            return False
