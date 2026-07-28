#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mndpsingh287 WP File Manager v6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Plugin File Manager (wp-file-manager) Backup Disclosure Detection',
        'description': 'mndpsingh287 WP File Manager v6.4 and lower fails to restrict external access to the fm_backups directory with a .htaccess file. This results in the ability for unauthenticated users to browse and download any site backups, which sometimes include full database backups, that the plugin has taken.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'wordpress', 'backups', 'plugin', 'webdesi9', 'vuln'],
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
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://zeroaptitude.com/zerodetail/wordpress-plugin-bug-hunting-part-1/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-24312',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Elsfa7-110/kenzer-templates',
            'https://github.com/StarCrossPortal/scalpel',
        ],
        'cve': 'CVE-2020-24312',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/uploads/wp-file-manager-pro/fm_backup/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Index of', 'wp-content/uploads/wp-file-manager-pro/fm_backup', 'backup_',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WordPress Plugin File Manager (wp-file-manager) Backup Disclosure detected",
                path='/wp-content/uploads/wp-file-manager-pro/fm_backup/',
            )
            return True
        return False

